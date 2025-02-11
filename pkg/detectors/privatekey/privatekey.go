package privatekey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	regexp "github.com/wasilibs/go-re2"
	"golang.org/x/crypto/ssh"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	IncludeExpired bool
	client         *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ interface {
	detectors.Detector
	detectors.MaxSecretSizeProvider
	detectors.CustomFalsePositiveChecker
} = (*Scanner)(nil)

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_PrivateKey
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"private key"}
}

func (s Scanner) Description() string {
	return "Private keys are used for securely connecting and authenticating to various systems and services. Exposure of private keys can lead to unauthorized access and data breaches."
}

// MaxSecretSize returns the maximum size of a secret that this detector can find.
func (s Scanner) MaxSecretSize() int64 { return 4096 }

func (s Scanner) IsFalsePositive(_ detectors.Result) (bool, string) {
	return false, ""
}

var keyPat = regexp.MustCompile(`(?i)-----\s*?BEGIN[ A-Z0-9_-]*?PRIVATE KEY\s*?-----[\s\S]*?----\s*?END[ A-Z0-9_-]*? PRIVATE KEY\s*?-----`)

// FromData will find and optionally verify Privatekey secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	logCtx := logContext.AddLogger(ctx)
	logger := logCtx.Logger().WithName("privatekey")
	dataStr := string(data)

	// Deduplicate matches.
	matches := make(map[string]struct{})
	for _, match := range keyPat.FindAllString(dataStr, -1) {
		if len(match) < 64 {
			continue
		}
		if detectors.StringShannonEntropy(match) < 3.5 {
			continue
		}
		matches[match] = struct{}{}
	}

	// Process matches.
	normalizedKeys := make(map[string]struct{})
	for match := range matches {
		key, err := normalizeMatch([]byte(match))
		if err != nil {
			if !errors.Is(err, errBase64) {
				logger.Error(err, "Failed to normalize private key", "match", match)
			}
			continue
		}
		if _, ok := normalizedKeys[key]; ok {
			continue
		}
		normalizedKeys[key] = struct{}{}

		r := detectors.Result{
			DetectorType: s.Type(),
			Raw:          []byte(key),
			Redacted:     key[0:64],
			ExtraData:    make(map[string]string),
		}

		var (
			passphrase  string
			fingerprint string
		)
		parsedKey, err := ssh.ParseRawPrivateKey([]byte(key))
		if err != nil {
			if strings.Contains(err.Error(), "private key is passphrase protected") {
				r.ExtraData["encrypted"] = "true"
				parsedKey, passphrase, err = Crack([]byte(key))
				if err != nil {
					r.SetVerificationError(err, key)
					goto End
				}
				if passphrase != "" {
					r.ExtraData["cracked_encryption_passphrase"] = "true"
				}
			} else if strings.Contains(err.Error(), "ssh: unsupported key type \"ENCRYPTED PRIVATE KEY\"") {
				// https://github.com/golang/go/issues/41949
				r.ExtraData["encrypted"] = "true"
				r.SetVerificationError(err, key)
				goto End
			} else {
				// logger.Error(err, "Failed to parse private key", "match", match, "normalized", key)
				r.SetVerificationError(err, key)
				goto End
			}
		}

		if verify {
			fingerprint, err = FingerprintPEMKey(parsedKey)
			if err != nil {
				r.SetVerificationError(err, key)
				goto End
			}

			var (
				wg                 sync.WaitGroup
				extraData          = newExtraData()
				verificationErrors = NewVerificationErrors(3)
			)
			if s.client == nil {
				s.client = common.RetryableHTTPClient()
			}

			// Look up certificate information.
			wg.Add(1)
			go func() {
				defer wg.Done()
				data, err := lookupFingerprintCertificateUrls(ctx, s.client, fingerprint, s.IncludeExpired)
				if err == nil {
					if data != nil {
						extraData.Add("certificate_urls", strings.Join(data.CertificateURLs, ", "))
					}
				} else {
					verificationErrors.Add(err)
				}
			}()

			// Test SSH key against github.com
			wg.Add(1)
			go func() {
				defer wg.Done()
				user, err := VerifyGitHubUser(ctx, parsedKey)
				if err != nil && !errors.Is(err, errPermissionDenied) {
					verificationErrors.Add(err)
				}
				if user != nil {
					extraData.Add("github_user", *user)
				}
			}()

			// Test SSH key against gitlab.com
			wg.Add(1)
			go func() {
				defer wg.Done()
				user, err := VerifyGitLabUser(ctx, parsedKey)
				if err != nil && !errors.Is(err, errPermissionDenied) {
					verificationErrors.Add(err)
				}
				if user != nil {
					extraData.Add("gitlab_user", *user)
				}
			}()

			wg.Wait()
			if len(extraData.data) > 0 {
				r.Verified = true
				for k, v := range extraData.data {
					r.ExtraData[k] = v
				}

				// enabled th
				r.AnalysisInfo = map[string]string{
					"token": key,
				}
			} else {
				r.ExtraData = nil
			}
			if len(verificationErrors.Errors) > 0 {
				r.SetVerificationError(fmt.Errorf("verification failures: %s", strings.Join(verificationErrors.Errors, ", ")), key)
			}
		}

	End:
		// Sanity check for any gaps with the new implementation.
		// There's probably a better way to do this.
		{
			oldKey := NormalizeOld(match)
			if parsedKey == nil {
				if parsedOldKey, _ := ssh.ParseRawPrivateKey([]byte(oldKey)); parsedOldKey != nil {
					logger.Info("New logic missed private key", "old", oldKey, "new", key)
				}
			}
		}

		if len(r.ExtraData) == 0 {
			r.ExtraData = nil
		}
		results = append(results, r)
	}

	return results, nil
}

type result struct {
	CertificateURLs []string
	GitHubUsername  string
}

func lookupFingerprintCertificateUrls(
	ctx context.Context,
	client *http.Client,
	publicKeyFingerprintInHex string,
	includeExpired bool,
) (*result, error) {
	results, err := LookupFingerprint(
		ctx,
		client,
		publicKeyFingerprintInHex,
	)
	if err != nil {
		return nil, err
	}

	var data *result
	seen := map[string]struct{}{}
	for _, r := range results.CertificateResults {
		if _, ok := seen[r.CertificateFingerprint]; ok {
			continue
		}
		if !includeExpired && time.Since(r.ExpirationTimestamp) > 0 {
			continue
		}
		if data == nil {
			data = &result{}
		}
		data.CertificateURLs = append(data.CertificateURLs, fmt.Sprintf("https://crt.sh/?q=%s", r.CertificateFingerprint))
		seen[r.CertificateFingerprint] = struct{}{}
	}

	return data, nil
}

func LookupFingerprint(ctx context.Context, client *http.Client, publicKeyFingerprintInHex string) (*DriftwoodResult, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://keychecker.trufflesecurity.com/fingerprint/%s", publicKeyFingerprintInHex), nil)
	if err != nil {
		return nil, err
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	var results DriftwoodResult
	err = json.NewDecoder(res.Body).Decode(&results)
	if err != nil {
		return nil, err
	}
	return &results, nil
}

type DriftwoodResult struct {
	CertificateResults []struct {
		Domains                []string  `json:",omitempty"`
		CertificateFingerprint string    `json:"CertificateFingerprint"`
		ExpirationTimestamp    time.Time `json:"ExpirationTimestamp"`
		IssuerName             string    `json:",omitempty"` // CA information
		SubjectName            string    `json:",omitempty"` // Certificate subject
		IssuerOrganization     []string  `json:",omitempty"` // CA organization(s)
		SubjectOrganization    []string  `json:",omitempty"` // Subject organization(s)
		KeyUsages              []string  `json:",omitempty"` // e.g., ["DigitalSignature", "KeyEncipherment"]
		ExtendedKeyUsages      []string  `json:",omitempty"` // e.g., ["ServerAuth", "ClientAuth"]
		SubjectKeyID           string    `json:",omitempty"` // hex encoded
		AuthorityKeyID         string    `json:",omitempty"` // hex encoded
		SerialNumber           string    `json:",omitempty"` // hex encoded
	} `json:"CertificateResults"`
	GitHubSSHResults []struct {
		Username string `json:"Username"`
	} `json:"GitHubSSHResults"`
}

type extraData struct {
	mutex sync.Mutex
	data  map[string]string
}

func newExtraData() *extraData {
	return &extraData{
		data: make(map[string]string),
	}
}

func (e *extraData) Add(key string, value string) {
	e.mutex.Lock()
	e.data[key] = value
	e.mutex.Unlock()
}

type VerificationErrors struct {
	mutex  sync.Mutex
	Errors []string
}

func NewVerificationErrors(capacity int) *VerificationErrors {
	return &VerificationErrors{
		Errors: make([]string, 0, capacity),
	}
}

func (e *VerificationErrors) Add(err error) {
	e.mutex.Lock()
	e.Errors = append(e.Errors, err.Error())
	e.mutex.Unlock()
}

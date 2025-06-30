package ibmclouduserkey

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_IbmCloudUserKey
}

func (s Scanner) Description() string {
	return "IBM Cloud is a suite of cloud computing services from IBM that offers both platform as a service (PaaS) and infrastructure as a service (IaaS). IBM Cloud API keys can be used to access and manage IBM Cloud services and resources."
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"ibm"}
}

var (
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"ibm"}) + `\b([\w-]{44})\b`)
)

// FromData will find and optionally verify IbmCloudUserKey secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// Deduplicate
	keyMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		m := match[1]
		if detectors.StringShannonEntropy(m) < 4 {
			continue
		}
		keyMatches[m] = struct{}{}
	}

	// Process
	for key := range keyMatches {
		r := detectors.Result{
			DetectorType: detectorspb.DetectorType_IbmCloudUserKey,
			Raw:          []byte(key),
		}

		if verify {
			if s.client == nil {
				s.client = common.SaneHttpClient()
			}

			isVerified, vErr := verifyMatch(ctx, s.client, key)
			r.Verified = isVerified
			r.SetVerificationError(vErr, key)
		}

		results = append(results, r)
	}

	return results, nil
}

func verifyMatch(ctx context.Context, client *http.Client, key string) (bool, error) {
	payload := strings.NewReader(`apikey=` + key + `&grant_type=urn%3Aibm%3Aparams%3Aoauth%3Agrant-type%3Aapikey`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://iam.cloud.ibm.com/identity/token", payload)
	if err != nil {
		return false, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic Yng6Yng=")
	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusBadRequest:
		var errResp errorResponse
		if err := json.NewDecoder(res.Body).Decode(&errResp); err != nil {
			return false, err
		}

		// Key is not valid.
		// https://www.ibm.com/docs/sk/cloud-private/3.2.x?topic=service-troubleshooting-key-management-plug-in#api
		if errResp.ErrorCode == "BXNIM0415E" {
			return false, nil
		}

		return false, fmt.Errorf("unexpected error (400): code=%q, message=%q", res.StatusCode, errResp.ErrorMessage)
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

type errorResponse struct {
	ErrorCode    string `json:"errorCode"`
	ErrorMessage string `json:"errorMessage"`
}

package gitlab

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
	detectors.EndpointSetter
}

// Ensure the Scanner satisfies the interfaces at compile time.
var (
	_ interface {
		detectors.Detector
		detectors.Versioner
		detectors.CloudProvider
		detectors.EndpointCustomizer
	} = (*Scanner)(nil)
)

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Gitlab
}

func (s Scanner) Description() string {
	return "GitLab is a web-based DevOps lifecycle tool that provides a Git repository manager providing wiki, issue-tracking, and CI/CD pipeline features. GitLab API tokens can be used to access and modify repository data and other resources."
}

func (Scanner) Version() int          { return 1 }
func (Scanner) CloudEndpoint() string { return "https://gitlab.com" }

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"gitlab"}
}

var (
	keyPat             = regexp.MustCompile(detectors.PrefixRegex([]string{"gitlab"}) + `\b([a-zA-Z0-9][a-zA-Z0-9\-=_]{19,21})\b`)
	BlockedUserMessage = "403 Forbidden - Your account has been blocked"
)

// FromData will find and optionally verify Gitlab secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// Deduplicate matches.
	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		// ignore v2 detectors which have a prefix of `glpat-`
		if strings.Contains(match[0], "glpat-") {
			continue
		}

		m := match[1]
		if detectors.StringShannonEntropy(m) < 3.75 {
			continue
		}
		uniqueMatches[m] = struct{}{}
	}

	// Process matches.
	for token := range uniqueMatches {
		r := detectors.Result{
			DetectorType: s.Type(),
			Raw:          []byte(token),
			ExtraData: map[string]string{
				"rotation_guide": "https://howtorotate.com/docs/tutorials/gitlab/",
				"version":        fmt.Sprintf("%d", s.Version()),
			},
		}

		if verify {
			if s.client == nil {
				s.client = common.SaneHttpClient()
			}

			isVerified, extraData, analysisInfo, verificationErr := s.verifyGitlab(ctx, s.client, token)
			r.Verified = isVerified
			for key, value := range extraData {
				r.ExtraData[key] = value
			}

			r.SetVerificationError(verificationErr, token)
			r.AnalysisInfo = analysisInfo
		}

		results = append(results, r)
	}

	return results, nil
}

func (s Scanner) verifyGitlab(ctx context.Context, client *http.Client, resMatch string) (bool, map[string]string, map[string]string, error) {
	// there are 4 read 'scopes' for a gitlab token: api, read_user, read_repo, and read_registry
	// they all grant access to different parts of the API. I couldn't find an endpoint that every
	// one of these scopes has access to, so we just check an example endpoint for each scope. If any
	// of them contain data, we know we have a valid key, but if they all fail, we don't
	for _, baseURL := range s.Endpoints() {
		// test `read_user` scope
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/api/v4/user", nil)
		if err != nil {
			continue
		}

		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", resMatch))
		res, err := client.Do(req)
		if err != nil {
			return false, nil, nil, err
		}
		defer func() {
			_, _ = io.Copy(io.Discard, res.Body)
			_ = res.Body.Close()
		}()

		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			return false, nil, nil, err
		}

		analysisInfo := map[string]string{
			"key":  resMatch,
			"host": baseURL,
		}

		switch res.StatusCode {
		case http.StatusOK:
			// 200 means good key and has `read_user` scope
			return json.Valid(bodyBytes), nil, analysisInfo, nil
		case http.StatusForbidden:
			// check if the user account is blocked or not
			stringBody := string(bodyBytes)
			if strings.Contains(stringBody, BlockedUserMessage) {
				return true, map[string]string{
					"blocked": "True",
				}, analysisInfo, nil
			}

			// Good key but not the right scope
			return true, nil, analysisInfo, nil
		case http.StatusUnauthorized:
			// Nothing to do; zero values are the ones we want
			return false, nil, nil, nil
		default:
			return false, nil, nil, fmt.Errorf("unexpected HTTP response status %d, body = %q", res.StatusCode, string(bodyBytes))
		}
	}

	return false, nil, nil, nil
}

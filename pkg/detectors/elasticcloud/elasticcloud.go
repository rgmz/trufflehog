package elasticcloud

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
	return detectorspb.DetectorType_ElasticCloud
}

func (s Scanner) Description() string {
	return "Elastic Cloud is a Elasticsearch cloud service. With a valid Elastic Cloud API key, you can access the API from its base URL at api.elastic-cloud.com"
}

func (s Scanner) Keywords() []string {
	return []string{"essu_"}
}

var (
	keyPat = regexp.MustCompile(`\b(essu_[a-zA-Z0-9+/]{24,}={0,3})`)
)

// FromData will find and optionally verify Apifonica secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		m := match[1]
		if detectors.StringShannonEntropy(m) < 4 {
			continue
		}
		uniqueMatches[m] = struct{}{}
	}

	for match := range uniqueMatches {
		r := detectors.Result{
			DetectorType: detectorspb.DetectorType_ElasticCloud,
			Raw:          []byte(match),
		}

		if verify {
			if s.client == nil {
				s.client = common.SaneHttpClient()
			}

			isVerified, extraData, verificationErr := verifyAPIKey(ctx, s.client, match)
			r.Verified = isVerified
			r.ExtraData = extraData
			r.SetVerificationError(verificationErr, match)
		}

		results = append(results, r)
	}

	return
}

const elasticCloudAPIBaseURL = "https://api.elastic-cloud.com/api/v1"

func verifyAPIKey(ctx context.Context, c *http.Client, key string) (bool, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, elasticCloudAPIBaseURL+"/deployments", nil)
	if err != nil {
		return false, nil, err
	}

	req.Header.Set("accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("ApiKey %s", key))
	res, err := c.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	// 200 - key is valid
	// 401 - key is invalid
	// 403 - key is valid but does not have access to the deployments endpoint
	switch res.StatusCode {
	case http.StatusOK:
		var deployRes deploymentsResponse
		if err := json.NewDecoder(res.Body).Decode(&deployRes); err != nil {
			return false, nil, err
		}

		var extraData map[string]string
		if len(deployRes.Deployments) > 0 {
			var names []string
			for _, d := range deployRes.Deployments {
				names = append(names, d.Name)
			}
			extraData = map[string]string{
				"deployments": strings.Join(names, ","),
			}
		}
		return true, extraData, nil
	case http.StatusUnauthorized:
		// The secret is determinately not verified (nothing to do)
		return false, nil, nil
	case http.StatusForbidden:
		return true, nil, nil
	default:
		body, _ := io.ReadAll(res.Body)
		return false, nil, fmt.Errorf("unexpected HTTP response status %d, body=%q", res.StatusCode, string(body))
	}
}

// https://www.elastic.co/docs/api/doc/cloud/group/endpoint-deployments
type deploymentsResponse struct {
	Deployments []deployment
}

type deployment struct {
	Id   string `json:"id"`
	Name string `json:"name"`
}

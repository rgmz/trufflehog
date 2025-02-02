package newrelicpersonalapikey

import (
	"context"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"newrelic"}) + `\b([A-Za-z0-9_\.]{4}-[A-Za-z0-9_\.]{42})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"newrelic"}
}

// FromData will find and optionally verify NewRelicPersonalApiKey secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_NewRelicPersonalApiKey,
			Raw:          []byte(resMatch),
		}

		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", "https://api.newrelic.com/v2/users.json", nil)
			reqEU, errEU := http.NewRequestWithContext(ctx, "GET", "https://api.eu.newrelic.com/v2/users.json", nil)
			if err != nil || errEU != nil {
				continue
			}
			req.Header.Add("X-Api-Key", resMatch)
			reqEU.Header.Add("X-Api-Key", resMatch)

			res, err := client.Do(req)
			resEU, errEU := client.Do(reqEU)

			if err == nil {
				defer res.Body.Close()
				if res.StatusCode >= 200 && res.StatusCode < 300 {
					s1.Verified = true
				}
			} else if errEU == nil {
				defer resEU.Body.Close()
				if resEU.StatusCode >= 200 && resEU.StatusCode < 300 {
					s1.Verified = true
				}
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_NewRelicPersonalApiKey
}

func (s Scanner) Description() string {
	return "New Relic is a software analytics and performance monitoring company. New Relic Personal API keys can be used to access and manage your New Relic account and data."
}

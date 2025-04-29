package netlify

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.Versioner = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	keyPat = regexp.MustCompile(`\b(nfp_[a-zA-Z0-9_]{36})\b`)
)

func (Scanner) Version() int { return 2 }

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"nfp_"}
}

// FromData will find and optionally verify Netlify secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		m := match[1]
		if detectors.StringShannonEntropy(m) < 3 {
			continue
		}
		uniqueMatches[m] = struct{}{}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Netlify,
			Raw:          []byte(match),
		}
		s1.ExtraData = map[string]string{
			"rotation_guide": "https://howtorotate.com/docs/tutorials/netlify/",
			"version":        strconv.Itoa(s.Version()),
		}

		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", "https://api.netlify.com/api/v1/sites", nil)
			if err != nil {
				continue
			}
			req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", match))
			res, err := client.Do(req)
			if err != nil {
				s1.SetVerificationError(err)
			} else {
				defer func() {
					_, _ = io.Copy(io.Discard, res.Body)
					_ = res.Body.Close()
				}()
				switch res.StatusCode {
				case http.StatusOK:
					s1.Verified = true
				case http.StatusUnauthorized:
					// Do nothing.
				default:
					body, _ := io.ReadAll(res.Body)
					s1.SetVerificationError(fmt.Errorf("unexpected response %d: %q", res.StatusCode, string(body)))
				}
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Netlify
}

func (s Scanner) Description() string {
	return "Netlify is a cloud platform for web developers that provides hosting and serverless backend services for web applications and static websites. Netlify API keys can be used to manage sites, deploy applications, and access various services offered by the platform."
}

package privacy

import (
	"context"
	"fmt"
	"io"
	"net/http"

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
	return detectorspb.DetectorType_Privacy
}

func (s Scanner) Description() string {
	return "Privacy provides virtual cards for secure online payments. Privacy API keys can be used to manage and create these virtual cards."
}

var (
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"privacy"}) + `\b([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"privacy.com"}
}

// FromData will find and optionally verify Privacy secrets in a given set of bytes.
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

	for key := range uniqueMatches {
		r := detectors.Result{
			DetectorType: detectorspb.DetectorType_Privacy,
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.privacy.com/v1/card?page=1&page_size=50", nil)
	if err != nil {
		return false, err
	}

	req.Header.Set("Authorization", "api-key "+key)
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
	case http.StatusUnauthorized:
		return false, nil
	default:
		body, _ := io.ReadAll(res.Body)
		return false, fmt.Errorf("unexpected HTTP response status %d, %q", res.StatusCode, string(body))
	}
}

package github

import (
	"context"
	"fmt"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	v1 "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/github/v1"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	v1.Scanner
}

// Ensure the Scanner satisfies the interfaces at compile time.
var _ interface {
	detectors.Detector
	detectors.Versioner
	detectors.CloudProvider
	detectors.EndpointCustomizer
} = (*Scanner)(nil)

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Github
}

func (s Scanner) Description() string {
	return "GitHub is a platform for version control and collaboration. Personal access tokens (PATs) can be used to access and modify repositories and other resources."
}

func (s Scanner) Version() int {
	return 2
}
func (Scanner) CloudEndpoint() string { return "https://api.github.com" }

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"}
}

var (
	// Oauth token
	// https://developer.github.com/v3/#oauth2-token-sent-in-a-header
	// Token type list:
	// https://github.blog/2021-04-05-behind-githubs-new-authentication-token-formats/
	// https://github.blog/changelog/2022-10-18-introducing-fine-grained-personal-access-tokens/
	keyPat = regexp.MustCompile(`\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[a-zA-Z0-9_]{36,255})\b`)
)

// FromData will find and optionally verify GitHub secrets in a given set of bytes.
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

	for token := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Github,
			Raw:          []byte(token),
			ExtraData: map[string]string{
				"rotation_guide": "https://howtorotate.com/docs/tutorials/github/",
				"version":        fmt.Sprintf("%d", s.Version()),
			},
			AnalysisInfo: map[string]string{"key": token},
		}

		if verify {
			client := common.SaneHttpClient()

			isVerified, userResponse, headers, err := s.VerifyGithub(ctx, client, token)
			s1.Verified = isVerified
			s1.SetVerificationError(err, token)

			if userResponse != nil {
				v1.SetUserResponse(userResponse, &s1)
			}
			if headers != nil {
				v1.SetHeaderInfo(headers, &s1)
			}
		}

		results = append(results, s1)
	}

	return
}

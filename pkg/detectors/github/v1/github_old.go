package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{ detectors.EndpointSetter }

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
	return "GitHub is a web-based platform used for version control and collaborative software development. GitHub tokens can be used to access and modify repositories and other resources."
}

func (Scanner) Version() int          { return 1 }
func (Scanner) CloudEndpoint() string { return "https://api.github.com" }

var (
	keyPat = regexp.MustCompile(`(?:(?i:github|token)|(?-i:GH|gh|HUB|[Hh]ub|PAT|[Pp]at|OCTO|[Oo]cto))[^\.].{0,40}[ =:'"]+([a-f0-9]{40})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"github", "gh", "hub", "pat", "token", "octo"}
}

// FromData will find and optionally verify GitHub secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		m := match[1]
		// Ignore low-entropy matches.
		if detectors.StringShannonEntropy(m) < 3 {
			continue
		}
		// Ignore githubusercontent.
		// https://github.com/trufflesecurity/trufflehog/issues/3664
		pat := regexp.MustCompile(`https://avatars\d?\.githubusercontent\.com/u/[\w?=&-]{0,25}` + m)
		if pat.MatchString(dataStr) {
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
				SetUserResponse(userResponse, &s1)
			}
			if headers != nil {
				SetHeaderInfo(headers, &s1)
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) VerifyGithub(ctx context.Context, client *http.Client, token string) (bool, *UserRes, *HeaderInfo, error) {
	// https://developer.github.com/v3/users/#get-the-authenticated-user
	var requestErr error
	for _, url := range s.Endpoints() {
		requestErr = nil

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/user", url), nil)
		if err != nil {
			continue
		}

		req.Header.Set("Content-Type", "application/json; charset=utf-8")
		req.Header.Set("Authorization", fmt.Sprintf("token %s", token))
		res, err := client.Do(req)
		if err != nil {
			return false, nil, nil, err
		}
		defer func() {
			_, _ = io.Copy(io.Discard, res.Body)
			_ = res.Body.Close()
		}()

		switch res.StatusCode {
		case http.StatusOK:
			var userResponse UserRes

			if err = json.NewDecoder(res.Body).Decode(&userResponse); err != nil {
				return false, nil, nil, err
			}
			// GitHub does not seem to consistently return this header.
			scopes := res.Header.Get("X-OAuth-Scopes")
			expiry := res.Header.Get("github-authentication-token-expiration")
			return true, &userResponse, &HeaderInfo{Scopes: scopes, Expiry: expiry}, nil
		case http.StatusUnauthorized:
			return false, nil, nil, err
		default:
			body, _ := io.ReadAll(res.Body)
			return false, nil, nil, fmt.Errorf("unexpected response: %d, '%s'", res.StatusCode, string(body))
		}
	}
	return false, nil, nil, requestErr
}

// TODO: Add secret context?? Information about access, ownership etc
type UserRes struct {
	Login     string `json:"login"`
	Type      string `json:"type"`
	SiteAdmin bool   `json:"site_admin"`
	Name      string `json:"name"`
	Company   string `json:"company"`
	UserURL   string `json:"html_url"`
	Email     string `json:"email"`
	Location  string `json:"location"`
	// Included in GitHub Enterprise Server.
	LdapDN string `json:"ldap_dn"`
}

type HeaderInfo struct {
	Scopes string `json:"X-OAuth-Scopes"`
	Expiry string `json:"github-authentication-token-expiration"`
}

func SetUserResponse(userResponse *UserRes, s1 *detectors.Result) {
	s1.ExtraData["username"] = userResponse.Login
	s1.ExtraData["url"] = userResponse.UserURL
	s1.ExtraData["account_type"] = userResponse.Type

	if userResponse.SiteAdmin {
		s1.ExtraData["site_admin"] = "true"
	}
	if userResponse.Name != "" {
		s1.ExtraData["name"] = userResponse.Name
	}
	if userResponse.Company != "" {
		s1.ExtraData["company"] = userResponse.Company
	}
	if userResponse.LdapDN != "" {
		s1.ExtraData["ldap_dn"] = userResponse.LdapDN
	}

	// email & location if user has made them public
	if userResponse.Email != "" {
		s1.ExtraData["email"] = userResponse.Email
	}
	if userResponse.Location != "" {
		s1.ExtraData["location"] = userResponse.Location
	}
}

func SetHeaderInfo(headers *HeaderInfo, s1 *detectors.Result) {
	if headers.Scopes != "" {
		s1.ExtraData["scopes"] = headers.Scopes
	}
	if headers.Expiry != "" {
		s1.ExtraData["expiry"] = headers.Expiry
	}
}

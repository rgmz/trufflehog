package github

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern = `[{
		"_id": "1a8d0cca-e1a9-4318-bc2f-f5658ab2dcb5",
		"name": "Github",
		"type": "Detector",
		"api": true,
		"authentication_type": "",
		"verification_url": "https://api.example.com/example",
		"test_secrets": {
			"github_secret": "abc123def4567890abcdef1234567890abcdef12"
		},
		"expected_response": "200",
		"method": "GET",
		"deprecated": false
	}]`
	secret = "abc123def4567890abcdef1234567890abcdef12"
)

func TestGithub_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern",
			input: validPattern,
			want:  []string{secret},
		},

		// Invalid
		{
			name:  "invalid - uppercase",
			input: `token = "EF321DEC2ADAB597C9B1727638A5185EAC7CEADB"`,
		},
		{
			name:  "invalid - low entropy",
			input: `gh_token = xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`,
		},
		{

			name: "invalid - githubusercontent",
			input: `
      {
        github: "zpinto",
        name: "Zachary Pinto",
        shortname: "Zach",
        university: "University of California, Irvine",
        city: "Irvine",
        avatar: "https://avatars3.githubusercontent.com/u/20071182?s=460&u=df311dec2adab597c9b1727638a5385eac7ceadb&v=4",
        url: "/preview-template/campus-experts/campus-experts.github.io/pr/3628zpinto"
      },
	- login: edreisMu
	  count: 1.0209057574170197
	  avatarUrl: https://avatars.githubusercontent.com/u/16641288?u=f659a34367a54ea7ac49bc2a51ac27f4a72c770b&v=4
	  url: https://github.com/edreisMu
`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Errorf("error = %v", err)
				return
			}

			if len(results) != len(test.want) {
				if len(results) == 0 {
					t.Errorf("did not receive result")
				} else {
					t.Errorf("expected %d results, received %d", len(test.want), len(results))
				}
				return
			}

			actual := make(map[string]struct{}, len(results))
			for _, r := range results {
				if len(r.RawV2) > 0 {
					actual[string(r.RawV2)] = struct{}{}
				} else {
					actual[string(r.Raw)] = struct{}{}
				}
			}
			expected := make(map[string]struct{}, len(test.want))
			for _, v := range test.want {
				expected[v] = struct{}{}
			}

			if diff := cmp.Diff(expected, actual); diff != "" {
				t.Errorf("%s diff: (-want +got)\n%s", test.name, diff)
			}
		})
	}
}

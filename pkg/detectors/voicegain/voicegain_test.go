package voicegain

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern   = "ey7nVWxLrVTPaolyqAYxmedMyueqpSQ6eIfX.ey582H2Ghcpty-_E0Wn4syTEdwAdXRF6eYyKgHveC26fBGQ4BiZIS30BcPrr1JG2xiFV4-bEOzVAMcWEQkh-THo0Z3RT6Os45ZGD28dlaiicZH.i4G5a88NkP82UpJoh3vW-sHOBx-uX1tYwyGcxykJO55"
	invalidPattern = "ay7nVWxLrVTPaolyqAYxmedMyueqpSQ6eIfX.ey582H2Ghcpty-_E0Wn4syTEdwAdXRF6eYyKgHveC26fBGQ4BiZIS30BcPrr1JG2xiFV4-bEOzVAMcWEQkh-THo0Z3RT6Os45ZGD28dlaiicZH.i4G5a88NkP82UpJoh3vW-sHOBx-uX1tYwyGcxykJO55"
	keyword        = "voicegain"
)

func TestVoicegain_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword voicegain",
			input: fmt.Sprintf("%s token = '%s'", keyword, validPattern),
			want:  []string{validPattern},
		},
		{
			name:  "valid pattern - ignore duplicate",
			input: fmt.Sprintf("%s token = '%s' | '%s'", keyword, validPattern, validPattern),
			want:  []string{validPattern},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("%s = '%s'", keyword, invalidPattern),
			want:  []string{},
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
					t.Errorf("expected %d results, only received %d", len(test.want), len(results))
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

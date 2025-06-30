package langfuse

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestLangfuse_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "typical pattern",
			input: `langfuse_public_key = pk-lf-85bd9970-f7fd-4683-bdcb-e20563f405fc
                    langfuse_secret_key = sk-lf-6ca47579-5a0e-4450-85c0-149f1eb3793c`,
			want: []string{"sk-lf-6ca47579-5a0e-4450-85c0-149f1eb3793c"},
		},
		{
			name: "finds all matches",
			input: `langfuse_public_key1 = pk-lf-85bd9970-f7fd-4683-bdcb-e20563f405fc
                    langfuse_secret_key1 = sk-lf-6ca47579-5a0e-4450-85c0-149f1eb3793c
					langfuse_public_key2 = pk-lf-73efae6a-6638-4f78-889a-118db7852b51
                    langfuse_secret_key2 = sk-lf-7227ec1f-eb60-4e8e-9893-315a96b4ce31`,
			want: []string{"sk-lf-6ca47579-5a0e-4450-85c0-149f1eb3793c",
				"sk-lf-7227ec1f-eb60-4e8e-9893-315a96b4ce31"},
		},
		{
			name: "invalid pattern",
			input: `langfuse_public_key1 = pk-lf-invalid
                    langfuse_secret_key1 = sk-lf-invalid`,
			want: []string{},
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

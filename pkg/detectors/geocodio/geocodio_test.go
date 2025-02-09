package geocodio

import (
	"testing"
)

// var (
// 	validPattern = `[{
// 		"_id": "1a8d0cca-e1a9-4318-bc2f-f5658ab2dcb5",
// 		"name": "GeoCodio",
// 		"type": "Detector",
// 		"api": true,
// 		"authentication_type": "",
// 		"verification_url": "https://api.example.com/example",
// 		"test_secrets": {
// 			"geocodio_key": "ar71u7xpxt0rlecmb5iree5mjroggsf6l2kzf92",
// 			"geocodio_secret": "ftn+YYXO"
// 		},
// 		"expected_response": "200",
// 		"method": "GET",
// 		"deprecated": false
// 	}]`
// 	secrets = []string{
// 		"ar71u7xpxt0rlecmb5iree5mjroggsf6l2kzf92ftn+YYXO",
// 		"ar71u7xpxt0rlecmb5iree5mjroggsf6l2kzf92Detector", // TODO: secret pattern is too broad - simplify
// 	}
// )

func TestGeoCodio_Pattern(t *testing.T) {
	t.Skip()

	// d := Scanner{}
	// ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	//
	// tests := []struct {
	// 	name  string
	// 	input string
	// 	want  []string
	// }{
	// 	{
	// 		name:  "valid pattern",
	// 		input: validPattern,
	// 		want:  secrets,
	// 	},
	// }
	//
	// for _, test := range tests {
	// 	t.Run(test.name, func(t *testing.T) {
	// 		matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
	// 		if len(matchedDetectors) == 0 {
	// 			t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
	// 			return
	// 		}
	//
	// 		results, err := d.FromData(context.Background(), false, []byte(test.input))
	// 		if err != nil {
	// 			t.Errorf("error = %v", err)
	// 			return
	// 		}
	//
	// 		if len(results) != len(test.want) {
	// 			if len(results) == 0 {
	// 				t.Errorf("did not receive result")
	// 			}
	// 		}
	//
	// 		actual := make(map[string]struct{}, len(results))
	// 		for _, r := range results {
	// 			if len(r.RawV2) > 0 {
	// 				actual[string(r.RawV2)] = struct{}{}
	// 			} else {
	// 				actual[string(r.Raw)] = struct{}{}
	// 			}
	// 		}
	// 		expected := make(map[string]struct{}, len(test.want))
	// 		for _, v := range test.want {
	// 			expected[v] = struct{}{}
	// 		}
	//
	// 		if diff := cmp.Diff(expected, actual); diff != "" {
	// 			t.Errorf("%s diff: (-want +got)\n%s", test.name, diff)
	// 		}
	// 	})
	// }
}

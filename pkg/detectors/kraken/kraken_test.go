package kraken

import (
	"testing"
)

// var (
// 	validKeyPattern       = "m=MN/0yYJ/5xqpE15JYDJtCFdDF7RDLuiXtTiSF1FU1H9waiub1kgwI= "
// 	invalidKeyPattern     = "m=MN/0yYJ/5xqpE15JYDJtCFdDF7RDLuiXtTiSF1FU1H9waiub1kgwI="
// 	validPrivKeyPattern   = "Oe1xUe+sNT7F5SboHSpfCubMhJlAaghB3SZ=NMmkIHTSzWVoF3uTOnxv32cgI+WuEDXYS+z5MvX+q9IUJ1cYo=+ "
// 	invalidPrivKeyPattern = "Oe1xUe+sNT7F5SboHSpfCubMhJlAaghB3SZ=NMmkIHTSzWVoF3uTOnxv32cgI+WuEDXYS+z5MvX+q9IUJ1cYo=+"
// 	keyword               = "kraken"
// )

func TestKraken_Pattern(t *testing.T) {
	t.Skip()
	// d := Scanner{}
	// ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	// tests := []struct {
	// 	name  string
	// 	input string
	// 	want  []string
	// }{
	// 	{
	// 		name:  "valid pattern - with keyword kraken",
	// 		input: fmt.Sprintf("%s '%s' %s '%s'", keyword, validKeyPattern, keyword, validPrivKeyPattern),
	// 		want:  []string{strings.TrimSpace(validKeyPattern) + strings.TrimSpace(validPrivKeyPattern)},
	// 	},
	// 	{
	// 		name:  "invalid pattern",
	// 		input: fmt.Sprintf("%s key = '%s' secret = '%s'", keyword, invalidKeyPattern, invalidPrivKeyPattern),
	// 		want:  []string{},
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

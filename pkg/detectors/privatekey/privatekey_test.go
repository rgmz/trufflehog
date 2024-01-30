//go:build detectors
// +build detectors

package privatekey

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/kylelemons/godebug/pretty"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestPrivateKey_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "multi-line standard format",
			input: `-----BEGIN RSA PRIVATE KEY-----
MIICWQIBAAKBgHsSuRPLMDrxcwMB9P6ubGFGmlSvHvSXq2kfwycrcEKf/TCctShz
A2HYo2IWed8n1rqazlESHnhNmCWlFWIMMFWagZyDBy9yy71MhWISvoTuQVyCx/z3
q1v171fy+Ds5smKwZ8wK3bgwBTR7BTKfYNmearDZvPJgwK0jsYEJDZ/DAgElAoGA
MeT+7FlK53akP31VfAGF4j83pcp0VVI+kmbSk1bMpWN0e33M5uKE1KPvNZpowkCV
UpHJQ3YMWkj4ffbRUUM2L/jQmKkICf7vynIdq5cj+lF6lNXSzwq6pVR6/octdeKS
/70DuGcVG+LiRTu2mRb6mPY9bIJIvcgenXajnVanx9UCQQDRwf6oyU/EH4x+kw/X
QZi/RebtDPD1yIQuhVG8B1xkPxBsAywTwVDL7DSZ1BsbWJcl5HcXt/q0n/3NZ62X
Rr1VAkEAljSLsMOk5H7XCctEk3mCu1WgDtUvb/RRCBiBT+cic14OpVtytJMAeLeq
cAhIj54ef4hQPGKbAsQZ3E/X4EsotwJAa7alXZfPA9jZcW4c5Ciai7wcoz3/Mhrc
F+OYrKnVf5YBg5LtHua6yZT4aqswg6oIbWd7bQty5yG5rqrcmcphOQJAHGrOUd/T
FnjckyZ0wfRk11VjeG2Fg+IdKwuOFgkiMYB/T7da4+R1tfk7666KRK82M82uUJ0I
kdISuvpZRhwOnwJBAI34lnrN4bNcUVB5kAXT9huyH8tJomNdsJOufS3vCi5tKaqK
Ic3jMIwtyuXsn4NhJNUFlgfPL70CPtb3x/eePqw=
-----END RSA PRIVATE KEY-----`,
			want: []string{"-----BEGIN RSA PRIVATE KEY-----\nMIICWQIBAAKBgHsSuRPLMDrxcwMB9P6ubGFGmlSvHvSXq2kfwycrcEKf/TCctShz\nA2HYo2IWed8n1rqazlESHnhNmCWlFWIMMFWagZyDBy9yy71MhWISvoTuQVyCx/z3\nq1v171fy+Ds5smKwZ8wK3bgwBTR7BTKfYNmearDZvPJgwK0jsYEJDZ/DAgElAoGA\nMeT+7FlK53akP31VfAGF4j83pcp0VVI+kmbSk1bMpWN0e33M5uKE1KPvNZpowkCV\nUpHJQ3YMWkj4ffbRUUM2L/jQmKkICf7vynIdq5cj+lF6lNXSzwq6pVR6/octdeKS\n/70DuGcVG+LiRTu2mRb6mPY9bIJIvcgenXajnVanx9UCQQDRwf6oyU/EH4x+kw/X\nQZi/RebtDPD1yIQuhVG8B1xkPxBsAywTwVDL7DSZ1BsbWJcl5HcXt/q0n/3NZ62X\nRr1VAkEAljSLsMOk5H7XCctEk3mCu1WgDtUvb/RRCBiBT+cic14OpVtytJMAeLeq\ncAhIj54ef4hQPGKbAsQZ3E/X4EsotwJAa7alXZfPA9jZcW4c5Ciai7wcoz3/Mhrc\nF+OYrKnVf5YBg5LtHua6yZT4aqswg6oIbWd7bQty5yG5rqrcmcphOQJAHGrOUd/T\nFnjckyZ0wfRk11VjeG2Fg+IdKwuOFgkiMYB/T7da4+R1tfk7666KRK82M82uUJ0I\nkdISuvpZRhwOnwJBAI34lnrN4bNcUVB5kAXT9huyH8tJomNdsJOufS3vCi5tKaqK\nIc3jMIwtyuXsn4NhJNUFlgfPL70CPtb3x/eePqw=\n-----END RSA PRIVATE KEY-----\n"},
		},
		// https://github.com/chromium/chromium/blob/051a9895e753b1097b1b44bdd851d21366dc46ee/extensions/common/file_util_unittest.cc#L527
		{
			name: "multi-line with quotes",
			input: `constexpr std::string_view private_key =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKt02SR0FYaYy6fpW\n"
    "MAA+kU1BgK3d+OmmWfdr+JATIjhRkyeSF4lTd/71JQsyKqPzYkQPi3EeROWM+goTv\n"
    "EhJqq07q63BolpsFmlV+S4ny+sBA2B4aWwRYXlBWikdrQSA0mJMzvEHc6nKzBgXik\n"
    "QSVbyyBNAsxlDB9WaCxRVOpK3AgMBAAECgYBGvSPlrVtAOAQ2V8j9FqorKZA8SLPX\n"
    "IeJC/yzU3RB2nPMjI17aMOvrUHxJUhzMeh4jwabVvSzzDtKFozPGupW3xaI8sQdi2\n"
    "WWMTQIk/Q9HHDWoQ9qA6SwX2qWCc5SyjCKqVp78ye+000kqTJYjBsDgXeAlzKcx2B\n"
    "4GAAeWonDdkQJBANNb8wrqNWFn7DqyQTfELzcRTRnqQ/r1pdeJo6obzbnwGnlqe3t\n"
    "KhLjtJNIGrQg5iC0OVLWFuvPJs0t3z62A1ckCQQDPq2JZuwTwu5Pl4DJ0r9O1FdqN\n"
    "JgqPZyMptokCDQ3khLLGakIu+TqB9YtrzI69rJMSG2Egb+6McaDX+dh3XmR/AkB9t\n"
    "xJf6qDnmA2td/tMtTc0NOk8Qdg/fD8xbZ/YfYMnVoYYs9pQoilBaWRePDRNURMLYZ\n"
    "vHAI0Llmw7tj7jv17pAkEAz44uXRpjRKtllUIvi5pUENAHwDz+HvdpGH68jpU3hmb\n"
    "uOwrmnQYxaMReFV68Z2w9DcLZn07f7/R9Wn72z89CxwJAFsDoNaDes4h48bX7plct\n"
    "s9ACjmTwcCigZjN2K7AGv7ntCLF3DnV5dK0dTHNaAdD3SbY3jl29Rk2CwiURSX6Ee\n"
    "g==\n"
    "-----END PRIVATE KEY-----\n";`,
			want: []string{"-----BEGIN PRIVATE KEY-----\nMIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKt02SR0FYaYy6fpW\nMAA+kU1BgK3d+OmmWfdr+JATIjhRkyeSF4lTd/71JQsyKqPzYkQPi3EeROWM+goTv\nEhJqq07q63BolpsFmlV+S4ny+sBA2B4aWwRYXlBWikdrQSA0mJMzvEHc6nKzBgXik\nQSVbyyBNAsxlDB9WaCxRVOpK3AgMBAAECgYBGvSPlrVtAOAQ2V8j9FqorKZA8SLPX\nIeJC/yzU3RB2nPMjI17aMOvrUHxJUhzMeh4jwabVvSzzDtKFozPGupW3xaI8sQdi2\nWWMTQIk/Q9HHDWoQ9qA6SwX2qWCc5SyjCKqVp78ye+000kqTJYjBsDgXeAlzKcx2B\n4GAAeWonDdkQJBANNb8wrqNWFn7DqyQTfELzcRTRnqQ/r1pdeJo6obzbnwGnlqe3t\nKhLjtJNIGrQg5iC0OVLWFuvPJs0t3z62A1ckCQQDPq2JZuwTwu5Pl4DJ0r9O1FdqN\nJgqPZyMptokCDQ3khLLGakIu+TqB9YtrzI69rJMSG2Egb+6McaDX+dh3XmR/AkB9t\nxJf6qDnmA2td/tMtTc0NOk8Qdg/fD8xbZ/YfYMnVoYYs9pQoilBaWRePDRNURMLYZ\nvHAI0Llmw7tj7jv17pAkEAz44uXRpjRKtllUIvi5pUENAHwDz+HvdpGH68jpU3hmb\nuOwrmnQYxaMReFV68Z2w9DcLZn07f7/R9Wn72z89CxwJAFsDoNaDes4h48bX7plct\ns9ACjmTwcCigZjN2K7AGv7ntCLF3DnV5dK0dTHNaAdD3SbY3jl29Rk2CwiURSX6Ee\ng==\n-----END PRIVATE KEY-----\n"},
		},
		{
			name: "multi-line concatenation (java)",
			input: `public static String cveAttackModePrivateKey =
      "-----BEGIN RSA PRIVATE KEY-----\n" + "MIIEowIBAAKCAQEAuvBC2RJqGAbPg6HoJaOlT6L4tMwMzGUI8TptoBlStWe+TfRc\n"
          + "uPVfxI1U6g87/7B62768kuU55H8bd3Yd7nBmmdzuNthAdPDMXlrnIbOywG52iPtH\n"
          + "AV1U5Vk5QGuj39aSuLjpBSC4jUJPcdJENpmECVX+EeNwZlOEDfbtnpOTMRr/24r1\n"
          + "CLSMwp9gtaLnE6NJzh+ycTDgyrWK9OtNA+UqzwfNJ9BfE53u9JHJP/nWZopqlNQ2\n"
          + "6fgPASu8FULa8bmJ3kc0SZFCNvXyjZn7HVCwIno/ZEq7oN9tphmAPBwdfQhb2xmD\n"
          + "3gYeWrXNP/M+SKisaX1CVwaPPowjCQMbsmfC2wIDAQABAoIBAGtODOEzq8i86BMk\n"
          + "NfCdHgA3iVGmq1YMTPTDWDgFMS/GLDvtH+hfmShnBC4SrpsXv34x32bmw7OArtCE\n"
          + "8atzw8FgSzEaMu2tZ3Jl9bSnxNymy83XhyumWlwIOk/bOcb8EV6NbdyuqqETRi0M\n"
          + "yHEa7+q3/M5h4pwqJmwpqL5U8bHGVGXNEbiA/TneNyXjSn03uPYaKTw4R9EG951A\n"
          + "pCJf4Atba5VIfdZ59fx/6rxCuKjWlvZrklE3Cll/+A0dRN5vBSR+EBYgfedMPepM\n"
          + "6TYDOsQnsy1bFJjy+aE/kwYGgtjuHOlvCpwq90SY3WueXClDfioaJ/1S6QT3q8hf\n"
          + "UHodWxkCgYEA8X6+dybVvBgawxyYZEi1P/KNWC9tr2zdztnkDB4nn97UIJzxmjTh\n"
          + "s81EsX0Mt24DJg36HoX5x1lDHNrR2RvIEPy8vfzTdNVa6KP7E7CWUUcW39nmt/z7\n"
          + "ezlyZa8TVPBE/xvozdZuTAzd0rafUX3Ugqzn17MBshz07/K4Z0iy/C0CgYEAxiqm\n"
          + "J7ul9CmNVvCnQ19tvcO7kY8h9AYIEtrqf9ubiq9W7Ldf9mXIhlG3wr6U3dXuAVVa\n"
          + "4g9zkXr+N7BE4hlQcJpBn5ywtYfqzK1GRy+rfwPgC/JbWEnNDP8oYnZ8R6pkhyOC\n"
          + "zqDqCZPtnmD9Je/ifdmgIkkxQD25ktyCYMhPuCcCgYEAh/MQCkfEfxUay8gnSh1c\n"
          + "W9mSFJjuqJki7TXgmanIKMnqpUl1AZjPjsb56uk45XJ7N0sbCV/m04C+tVnCVPS8\n"
          + "1kNRhar054rMmLbnu5fnp23bxL0Ik39Jm38llXTP7zsrvGnbzzTt9sYvglXorpml\n"
          + "rsLj6ZwOUlTW1tXPVeWpTSkCgYBfAkGpWRlGx8lA/p5i+dTGn5pFPmeb9GxYheba\n"
          + "KDMZudkmIwD6RHBwnatJzk/XT+MNdpvdOGVDQcGyd2t/L33Wjs6ZtOkwD5suSIEi\n"
          + "TiOeAQChGbBb0v5hldAJ7R7GyVXrSMZFRPcQYoERZxTX5HwltHpHFepsD2vykpBb\n"
          + "0I4QDwKBgDRH3RjKJduH2WvHOmQmXqWwtkY7zkLwSysWTW5KvCEUI+4VHMggaQ9Z\n"
          + "YUXuHa8osFZ8ruJzSd0HTrDVuNTb8Q7XADOn4a5AGHu1Bhw996uNCP075dx8IOsl\n"
          + "B6zvMHB8rRW93GfFd08REpsgqSm+AL6iLlZHowC00FFPtLs9e7ci\n" + "-----END RSA PRIVATE KEY-----";`,
			want: []string{""},
		},
		{
			name: "multi-line concatenation (ruby)",
			input: `    key_data = "-----BEGIN DSA PRIVATE KEY-----\n"
    key_data += "MIIBugIBAAKBgQCUw7F/vKJT2Xsq+fIPVxNC/Dyk+dN9DWQT5RO56eIQasd+h6Fm\n"
    key_data += "q1qtQrJ/DOe3VjfUrSm7NN5NoIGOrGCSuQFthFmq+9Lpt6WIykB4mau5iE5orbKM\n"
    key_data += "xTfyu8LtntoikYKrlMB+UrmKDidvZ+7oWiC14imT+Px/3Q7naj0UmOrSTwIVAO25\n"
    key_data += "Yf3SYNtTYv8yzaV+X9yNr/AfAoGADAcEh2bdsrDhwhXtVi1L3cFQx1KpN0B07JLr\n"
    key_data += "gJzJcDLUrwmlMUmrXR2obDGfVQh46EFMeo/k3IESw2zJUS58FJW+sKZ4noSwRZPq\n"
    key_data += "mpBnERKpLOTcWMxUyV8ETsz+9oz71YEMjmR1qvNYAopXf5Yy+4Zq3bgqmMMQyM+K\n"
    key_data += "O1PdlCkCgYBmhSl9CVPgVMv1xO8DAHVhM1huIIK8mNFrzMJz+JXzBx81ms1kWSeQ\n"
    key_data += "OC/nraaXFTBlqiQsvB8tzr4xZdbaI/QzVLKNAF5C8BJ4ScNlTIx1aZJwyMil8Nzb\n"
    key_data += "+0YAsw5Ja+bEZZvEVlAYnd10qRWrPeEY1txLMmX3wDa+JvJL7fmuBgIUZoXsJnzs\n"
    key_data += "+sqSEhA35Le2kC4Y1/A=\n"
    key_data += "-----END DSA PRIVATE KEY-----\n"`,
			want: []string{""},
		},
		{
			name:  "",
			input: ``,
			want:  []string{""},
		},
		{
			name:  "one line newlines",
			input: `SUPERTOKENS_APPLE_SECRET_PRIVATE_KEY=-----BEGIN PRIVATE KEY-----\nMIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgu8gXs+XYkqXD6Ala9Sf/iJXzhbwcoG5dMh1OonpdJUmgCgYIKoZIzj0DAQehRANCAASfrvlFbFCYqn3I2zeknYXLwtH30JuOKestDbSfZYxZNMqhF/OzdZFTV0zc5u5s3eN+oCWbnvl0hM+9IW0UlkdA\n-----END PRIVATE KEY-----`,
			want:  []string{"-----BEGIN PRIVATE KEY-----\nMIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgu8gXs+XYkqXD6Ala9Sf/iJXzhbwcoG5dMh1OonpdJUmgCgYIKoZIzj0DAQehRANCAASfrvlFbFCYqn3I2zeknYXLwtH30JuOKestDbSfZYxZNMqhF/OzdZFTV0zc5u5s3eN+oCWbnvl0hM+9IW0UlkdA\n-----END PRIVATE KEY-----\n"},
		},
		// https://github.com/trufflesecurity/trufflehog/issues/2338
		{
			name:  "one line spaces",
			input: `private_key=-----BEGIN RSA PRIVATE KEY----- MIICWQIBAAKBgHsSuRPLMDrxcwMB9P6ubGFGmlSvHvSXq2kfwycrcEKf/TCctShz A2HYo2IWed8n1rqazlESHnhNmCWlFWIMMFWagZyDBy9yy71MhWISvoTuQVyCx/z3 q1v171fy+Ds5smKwZ8wK3bgwBTR7BTKfYNmearDZvPJgwK0jsYEJDZ/DAgElAoGA MeT+7FlK53akP31VfAGF4j83pcp0VVI+kmbSk1bMpWN0e33M5uKE1KPvNZpowkCV UpHJQ3YMWkj4ffbRUUM2L/jQmKkICf7vynIdq5cj+lF6lNXSzwq6pVR6/octdeKS /70DuGcVG+LiRTu2mRb6mPY9bIJIvcgenXajnVanx9UCQQDRwf6oyU/EH4x+kw/X QZi/RebtDPD1yIQuhVG8B1xkPxBsAywTwVDL7DSZ1BsbWJcl5HcXt/q0n/3NZ62X Rr1VAkEAljSLsMOk5H7XCctEk3mCu1WgDtUvb/RRCBiBT+cic14OpVtytJMAeLeq cAhIj54ef4hQPGKbAsQZ3E/X4EsotwJAa7alXZfPA9jZcW4c5Ciai7wcoz3/Mhrc F+OYrKnVf5YBg5LtHua6yZT4aqswg6oIbWd7bQty5yG5rqrcmcphOQJAHGrOUd/T FnjckyZ0wfRk11VjeG2Fg+IdKwuOFgkiMYB/T7da4+R1tfk7666KRK82M82uUJ0I kdISuvpZRhwOnwJBAI34lnrN4bNcUVB5kAXT9huyH8tJomNdsJOufS3vCi5tKaqK Ic3jMIwtyuXsn4NhJNUFlgfPL70CPtb3x/eePqw= -----END RSA PRIVATE KEY-----`,
			want:  []string{"-----BEGIN RSA PRIVATE KEY----- MIICWQIBAAKBgHsSuRPLMDrxcwMB9P6ubGFGmlSvHvSXq2kfwycrcEKf/TCctShz A2HYo2IWed8n1rqazlESHnhNmCWlFWIMMFWagZyDBy9yy71MhWISvoTuQVyCx/z3 q1v171fy+Ds5smKwZ8wK3bgwBTR7BTKfYNmearDZvPJgwK0jsYEJDZ/DAgElAoGA MeT+7FlK53akP31VfAGF4j83pcp0VVI+kmbSk1bMpWN0e33M5uKE1KPvNZpowkCV UpHJQ3YMWkj4ffbRUUM2L/jQmKkICf7vynIdq5cj+lF6lNXSzwq6pVR6/octdeKS /70DuGcVG+LiRTu2mRb6mPY9bIJIvcgenXajnVanx9UCQQDRwf6oyU/EH4x+kw/X QZi/RebtDPD1yIQuhVG8B1xkPxBsAywTwVDL7DSZ1BsbWJcl5HcXt/q0n/3NZ62X Rr1VAkEAljSLsMOk5H7XCctEk3mCu1WgDtUvb/RRCBiBT+cic14OpVtytJMAeLeq cAhIj54ef4hQPGKbAsQZ3E/X4EsotwJAa7alXZfPA9jZcW4c5Ciai7wcoz3/Mhrc F+OYrKnVf5YBg5LtHua6yZT4aqswg6oIbWd7bQty5yG5rqrcmcphOQJAHGrOUd/T FnjckyZ0wfRk11VjeG2Fg+IdKwuOFgkiMYB/T7da4+R1tfk7666KRK82M82uUJ0I kdISuvpZRhwOnwJBAI34lnrN4bNcUVB5kAXT9huyH8tJomNdsJOufS3vCi5tKaqK Ic3jMIwtyuXsn4NhJNUFlgfPL70CPtb3x/eePqw= -----END RSA PRIVATE KEY-----"},
		},

		// Invalid
		{
			name: "invalid key",
			input: `        "jwt-auth": {
            "key": "user-key",
            "public_key": "-----BEGIN PUBLIC KEY-----\n……\n-----END PUBLIC KEY-----",
            "private_key": "-----BEGIN RSA PRIVATE KEY-----\n……\n-----END RSA PRIVATE KEY-----",
            "algorithm": "RS256"
        }`,
		},
		{
			name: "start and end",
			input: `/* openssh private key file format */
#define MARK_BEGIN		"-----BEGIN OPENSSH PRIVATE KEY-----\n"
#define MARK_END		"-----END OPENSSH PRIVATE KEY-----\n"
#define MARK_BEGIN_LEN		(sizeof(MARK_BEGIN) - 1)
#define MARK_END_LEN		(sizeof(MARK_END) - 1)`,
		},
		{
			name:  "",
			input: ``,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			chunkSpecificDetectors := make(map[ahocorasick.DetectorKey]detectors.Detector, 2)
			ahoCorasickCore.PopulateMatchingDetectors(test.input, chunkSpecificDetectors)
			if len(chunkSpecificDetectors) == 0 {
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

func TestPrivatekey_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors4")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	secretTLS := testSecrets.MustGetField("PRIVATEKEY_TLS")
	secretGitHub := testSecrets.MustGetField("PRIVATEKEY_GITHUB")
	secretGitHubEncrypted := testSecrets.MustGetField("PRIVATEKEY_GITHUB_ENCRYPTED")
	secretInactive := testSecrets.MustGetField("PRIVATEKEY_UNVERIFIED")

	type args struct {
		ctx    context.Context
		data   []byte
		verify bool
	}

	tests := []struct {
		name    string
		s       Scanner
		args    args
		want    []detectors.Result
		wantErr bool
	}{
		{
			name: "found, unverified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find privatekey secret %s within", secretInactive)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_PrivateKey,
					Verified:     false,
					Redacted:     "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYw",
				},
				{
					DetectorType: detectorspb.DetectorType_PrivateKey,
					Verified:     false,
					Redacted:     "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgw",
				},
			},
			wantErr: false,
		},
		{
			name: "found TLS private key, verified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(secretTLS),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_PrivateKey,
					Verified:     true,
					Redacted:     "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgw",
					ExtraData: map[string]string{
						"certificate_urls": "https://crt.sh/?q=1e20c40deb44a8539dd3ac3e8c53b72750cb19f9, https://crt.sh/?q=0e9de31fb2ee16465a4d5d93b227d54f870326d1",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "found GitHub SSH private key, verified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(secretGitHub),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_PrivateKey,
					Verified:     true,
					Redacted:     "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5v",
					ExtraData: map[string]string{
						"github_user": "sirdetectsalot",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "found encrypted GitHub SSH private key, verified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(secretGitHubEncrypted),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_PrivateKey,
					Verified:     true,
					Redacted:     "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAACmFl",
					ExtraData: map[string]string{
						"github_user":                   "sirdetectsalot",
						"encrypted":                     "true",
						"cracked_encryption_passphrase": "true",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "not found",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte("You cannot find the secret within"),
				verify: true,
			},
			want:    nil,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Scanner{IncludeExpired: true}
			got, err := s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("PrivatekeyCI.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if os.Getenv("FORCE_PASS_DIFF") == "true" {
				return
			}
			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Fatal("no raw secret present")
				}
				got[i].Raw = nil
			}
			if diff := pretty.Compare(got, tt.want); diff != "" {
				t.Errorf("PrivatekeyCI.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
			}
		})
	}
}

func BenchmarkFromData(benchmark *testing.B) {
	ctx := context.Background()
	s := Scanner{}
	for name, data := range detectors.MustGetBenchmarkData() {
		benchmark.Run(name, func(b *testing.B) {
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				_, err := s.FromData(ctx, false, data)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func Test_lookupFingerprint(t *testing.T) {
	tests := []struct {
		name                      string
		publicKeyFingerprintInHex string
		wantFingerprints          bool
		wantErr                   bool
		includeExpired            bool
	}{
		{
			name:                      "got some",
			publicKeyFingerprintInHex: "4c5da06caa1c81df9c8e1abe43bac385de1bda76",
			wantFingerprints:          true,
			wantErr:                   false,
			includeExpired:            true,
		},
		{
			name:                      "got some",
			publicKeyFingerprintInHex: "none",
			wantFingerprints:          false,
			wantErr:                   false,
			includeExpired:            true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotFingerprints, err := lookupFingerprint(tt.publicKeyFingerprintInHex, tt.includeExpired)
			if (err != nil) != tt.wantErr {
				t.Errorf("lookupFingerprint() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotFingerprints != nil && len(gotFingerprints.CertificateURLs) > 0, tt.wantFingerprints) {
				t.Errorf("lookupFingerprint() = %v, want %v", gotFingerprints, tt.wantFingerprints)
			}
		})
	}
}

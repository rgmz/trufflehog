package privatekey

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestPrivateKey_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		// TODO: Test case with multiple slashes (gcp creds inside of base64-encoding)
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
			want: []string{"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAuvBC2RJqGAbPg6HoJaOlT6L4tMwMzGUI8TptoBlStWe+TfRc\nuPVfxI1U6g87/7B62768kuU55H8bd3Yd7nBmmdzuNthAdPDMXlrnIbOywG52iPtH\nAV1U5Vk5QGuj39aSuLjpBSC4jUJPcdJENpmECVX+EeNwZlOEDfbtnpOTMRr/24r1\nCLSMwp9gtaLnE6NJzh+ycTDgyrWK9OtNA+UqzwfNJ9BfE53u9JHJP/nWZopqlNQ2\n6fgPASu8FULa8bmJ3kc0SZFCNvXyjZn7HVCwIno/ZEq7oN9tphmAPBwdfQhb2xmD\n3gYeWrXNP/M+SKisaX1CVwaPPowjCQMbsmfC2wIDAQABAoIBAGtODOEzq8i86BMk\nNfCdHgA3iVGmq1YMTPTDWDgFMS/GLDvtH+hfmShnBC4SrpsXv34x32bmw7OArtCE\n8atzw8FgSzEaMu2tZ3Jl9bSnxNymy83XhyumWlwIOk/bOcb8EV6NbdyuqqETRi0M\nyHEa7+q3/M5h4pwqJmwpqL5U8bHGVGXNEbiA/TneNyXjSn03uPYaKTw4R9EG951A\npCJf4Atba5VIfdZ59fx/6rxCuKjWlvZrklE3Cll/+A0dRN5vBSR+EBYgfedMPepM\n6TYDOsQnsy1bFJjy+aE/kwYGgtjuHOlvCpwq90SY3WueXClDfioaJ/1S6QT3q8hf\nUHodWxkCgYEA8X6+dybVvBgawxyYZEi1P/KNWC9tr2zdztnkDB4nn97UIJzxmjTh\ns81EsX0Mt24DJg36HoX5x1lDHNrR2RvIEPy8vfzTdNVa6KP7E7CWUUcW39nmt/z7\nezlyZa8TVPBE/xvozdZuTAzd0rafUX3Ugqzn17MBshz07/K4Z0iy/C0CgYEAxiqm\nJ7ul9CmNVvCnQ19tvcO7kY8h9AYIEtrqf9ubiq9W7Ldf9mXIhlG3wr6U3dXuAVVa\n4g9zkXr+N7BE4hlQcJpBn5ywtYfqzK1GRy+rfwPgC/JbWEnNDP8oYnZ8R6pkhyOC\nzqDqCZPtnmD9Je/ifdmgIkkxQD25ktyCYMhPuCcCgYEAh/MQCkfEfxUay8gnSh1c\nW9mSFJjuqJki7TXgmanIKMnqpUl1AZjPjsb56uk45XJ7N0sbCV/m04C+tVnCVPS8\n1kNRhar054rMmLbnu5fnp23bxL0Ik39Jm38llXTP7zsrvGnbzzTt9sYvglXorpml\nrsLj6ZwOUlTW1tXPVeWpTSkCgYBfAkGpWRlGx8lA/p5i+dTGn5pFPmeb9GxYheba\nKDMZudkmIwD6RHBwnatJzk/XT+MNdpvdOGVDQcGyd2t/L33Wjs6ZtOkwD5suSIEi\nTiOeAQChGbBb0v5hldAJ7R7GyVXrSMZFRPcQYoERZxTX5HwltHpHFepsD2vykpBb\n0I4QDwKBgDRH3RjKJduH2WvHOmQmXqWwtkY7zkLwSysWTW5KvCEUI+4VHMggaQ9Z\nYUXuHa8osFZ8ruJzSd0HTrDVuNTb8Q7XADOn4a5AGHu1Bhw996uNCP075dx8IOsl\nB6zvMHB8rRW93GfFd08REpsgqSm+AL6iLlZHowC00FFPtLs9e7ci\n-----END RSA PRIVATE KEY-----\n"},
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
			want: []string{"-----BEGIN DSA PRIVATE KEY-----\nMIIBugIBAAKBgQCUw7F/vKJT2Xsq+fIPVxNC/Dyk+dN9DWQT5RO56eIQasd+h6Fm\nq1qtQrJ/DOe3VjfUrSm7NN5NoIGOrGCSuQFthFmq+9Lpt6WIykB4mau5iE5orbKM\nxTfyu8LtntoikYKrlMB+UrmKDidvZ+7oWiC14imT+Px/3Q7naj0UmOrSTwIVAO25\nYf3SYNtTYv8yzaV+X9yNr/AfAoGADAcEh2bdsrDhwhXtVi1L3cFQx1KpN0B07JLr\ngJzJcDLUrwmlMUmrXR2obDGfVQh46EFMeo/k3IESw2zJUS58FJW+sKZ4noSwRZPq\nmpBnERKpLOTcWMxUyV8ETsz+9oz71YEMjmR1qvNYAopXf5Yy+4Zq3bgqmMMQyM+K\nO1PdlCkCgYBmhSl9CVPgVMv1xO8DAHVhM1huIIK8mNFrzMJz+JXzBx81ms1kWSeQ\nOC/nraaXFTBlqiQsvB8tzr4xZdbaI/QzVLKNAF5C8BJ4ScNlTIx1aZJwyMil8Nzb\n+0YAsw5Ja+bEZZvEVlAYnd10qRWrPeEY1txLMmX3wDa+JvJL7fmuBgIUZoXsJnzs\n+sqSEhA35Le2kC4Y1/A=\n-----END DSA PRIVATE KEY-----\n"},
		},
		{
			// https://github.com/sailfishos/sailfish-secrets/blob/a066aa78078d20656068b4ab4102c57bcd13259c/plugins/exampleusbtokenplugin/exampleusbtokenplugin.cpp#L75
			name: "multi-line - encrypted header",
			input: `    // The passphrase for the following RSA key.pem is "12345" which must
    // be passed as the lockCode in order for the unlock operation to succeed.
    const QByteArray pemData(
       "-----BEGIN RSA PRIVATE KEY-----\n"
       "Proc-Type: 4,ENCRYPTED\n"
       "DEK-Info: AES-128-CBC,58909F0499FB07748B8159C42B84CA75\n"
       "\n"
       "DJyGd3AQ53uz0mwfuLZ7uQr+7W7TeS54nn7jvBfFS0MtDd5FtaKbir2FurW3fWet\n"
       "HebFzg8fUCrhY+/cGN5WfKjGoCHo5hsKxuKgowoBMwsgnU0khkjQMz3Jw6h6F7KT\n"
       "4SAhI02OPKQZD9g8YBzx4ui+LXpcBLS4pHf5KhY1WMq5CuPzafrqwl3jUdz1Qaiv\n"
       "JBePjlCBEXlUGemDNkNR4lzk8RuCs8kZKZo1iJd3W3YHpBhs9DyErBVbTkpCT7yA\n"
       "ELZ6w28pyFUbFFXm7GXhiokqjSfLFQH3MbPCUKVIbEVkHSP4FqoTDPnBdGlW+Fvq\n"
       "sALyqS9/NTsJ5jXF0CV2gEum4bRMalTyqQhHVihEWkuX8CRpmAP7/eoOjhN+ydVU\n"
       "ggkzxVyXRicpDBzt8r7MjmpO6zwuYmrsRwagaEh+aUokHU+Z++WelFXXai5b1uEO\n"
       "wjRxsjOmPP8R+VhFyyG4VvpzPT3yU4lMav+U3Z7hsaD0UzuJAmxMOMtatl3A6Pt6\n"
       "ME9p/B3ofcE0m1g9EhH7sBo6jMkrgG+pwtkIJ1xMbvYBjCPr2fTzhGgUuTkln1fp\n"
       "XrwNZeYIBhYhZ95imXfzZVEQOyJc8QHS0iJciodJDkbnlwenb2TccWkhJyxtoeF9\n"
       "RBmqJn5bbLjCVHRgmXj7OePAgQiYFoirQ6F/J1eKrVBSgLlR/gsPzqPisIlto9tx\n"
       "GaGsstuq6TLejSa8WEq1HzPaxccjOpR6tA0f2+xc9LweLB7nEnm82EvKFukk5e0i\n"
       "hVe/u6XQWw0FW11Wio2y87437BF93oytlPcHWQyB/fkS7FvMHxfnrnt2ybGbPnTL\n"
       "qODt2g4IziyNQF3PiMJOzYWSJ5JG0L0A8W0FK+Pb9G2jnQBAuPIpRSqQ7yUtBGh0\n"
       "slrxEGapCPZY3mccS1pLEzHBLFEUudWqhaNU8tmeBw48QBLrK2DE+kzr7bzLsdvH\n"
       "b27QEkGWvF+KgPbEqBKC3d9u4z4cWNHYuLRuiaE/2MbxAQ4yGcr4acahm2gjTPZg\n"
       "ajTbk50NZBj0L0AzHusODCssypnREnY/40v0VdIYNBcUf+fbSUXV5LNqblrnf6ra\n"
       "B2pzk+tKqE9QOBYz7HZ3Pkq9GeIVMGKDM71jczw5dFRPY58doU22C9fQzBQuasVn\n"
       "sSUusNkHOm0OM6VX2hXH/lhhZYLgvy5MSzpnSSwTv+4wFa1mzuvUJkyL4SPgZ2Nx\n"
       "XQr1ss88t7qAw0bQeLNmBIbQDVtlhQ3E/5qUuhNY8/P50vt8LmiCXJ/IvGxecJgS\n"
       "NtNAno1XcQ73A8Ri5d1zdu2+4GXkHUrSwVlFMZGmC3cXlO5nA8pkcVLl7vSQmib4\n"
       "tzR2wfVvj1X0W/NYrcnAQ6ooymhpE8yVCKKLw94YABOtiDP89YB4hdtzbfHOsEXP\n"
       "iHZB5uURv2uwE0s0f2zVRt3ryZZoF/Dgc9BD+6wcN8z/uK4ucaXuDmVJW8EX6V5U\n"
       "F3LPsdi3w2rx/pauRNQpTTIFpqtIrogSkTpWmQv3kIM4+Z62Y3X9Cr/61RpTZIF5\n"
       "6obcnqDfdVsOcLZIjLpXeoW3GQ7dakwe3gPwVvCEEDqNzTPosxKNCUKlzVasRECQ\n"
       "-----END RSA PRIVATE KEY-----\n");`,
			want: []string{"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,58909F0499FB07748B8159C42B84CA75\nDJyGd3AQ53uz0mwfuLZ7uQr+7W7TeS54nn7jvBfFS0MtDd5FtaKbir2FurW3fWet\nHebFzg8fUCrhY+/cGN5WfKjGoCHo5hsKxuKgowoBMwsgnU0khkjQMz3Jw6h6F7KT\n4SAhI02OPKQZD9g8YBzx4ui+LXpcBLS4pHf5KhY1WMq5CuPzafrqwl3jUdz1Qaiv\nJBePjlCBEXlUGemDNkNR4lzk8RuCs8kZKZo1iJd3W3YHpBhs9DyErBVbTkpCT7yA\nELZ6w28pyFUbFFXm7GXhiokqjSfLFQH3MbPCUKVIbEVkHSP4FqoTDPnBdGlW+Fvq\nsALyqS9/NTsJ5jXF0CV2gEum4bRMalTyqQhHVihEWkuX8CRpmAP7/eoOjhN+ydVU\nggkzxVyXRicpDBzt8r7MjmpO6zwuYmrsRwagaEh+aUokHU+Z++WelFXXai5b1uEO\nwjRxsjOmPP8R+VhFyyG4VvpzPT3yU4lMav+U3Z7hsaD0UzuJAmxMOMtatl3A6Pt6\nME9p/B3ofcE0m1g9EhH7sBo6jMkrgG+pwtkIJ1xMbvYBjCPr2fTzhGgUuTkln1fp\nXrwNZeYIBhYhZ95imXfzZVEQOyJc8QHS0iJciodJDkbnlwenb2TccWkhJyxtoeF9\nRBmqJn5bbLjCVHRgmXj7OePAgQiYFoirQ6F/J1eKrVBSgLlR/gsPzqPisIlto9tx\nGaGsstuq6TLejSa8WEq1HzPaxccjOpR6tA0f2+xc9LweLB7nEnm82EvKFukk5e0i\nhVe/u6XQWw0FW11Wio2y87437BF93oytlPcHWQyB/fkS7FvMHxfnrnt2ybGbPnTL\nqODt2g4IziyNQF3PiMJOzYWSJ5JG0L0A8W0FK+Pb9G2jnQBAuPIpRSqQ7yUtBGh0\nslrxEGapCPZY3mccS1pLEzHBLFEUudWqhaNU8tmeBw48QBLrK2DE+kzr7bzLsdvH\nb27QEkGWvF+KgPbEqBKC3d9u4z4cWNHYuLRuiaE/2MbxAQ4yGcr4acahm2gjTPZg\najTbk50NZBj0L0AzHusODCssypnREnY/40v0VdIYNBcUf+fbSUXV5LNqblrnf6ra\nB2pzk+tKqE9QOBYz7HZ3Pkq9GeIVMGKDM71jczw5dFRPY58doU22C9fQzBQuasVn\nsSUusNkHOm0OM6VX2hXH/lhhZYLgvy5MSzpnSSwTv+4wFa1mzuvUJkyL4SPgZ2Nx\nXQr1ss88t7qAw0bQeLNmBIbQDVtlhQ3E/5qUuhNY8/P50vt8LmiCXJ/IvGxecJgS\nNtNAno1XcQ73A8Ri5d1zdu2+4GXkHUrSwVlFMZGmC3cXlO5nA8pkcVLl7vSQmib4\ntzR2wfVvj1X0W/NYrcnAQ6ooymhpE8yVCKKLw94YABOtiDP89YB4hdtzbfHOsEXP\niHZB5uURv2uwE0s0f2zVRt3ryZZoF/Dgc9BD+6wcN8z/uK4ucaXuDmVJW8EX6V5U\nF3LPsdi3w2rx/pauRNQpTTIFpqtIrogSkTpWmQv3kIM4+Z62Y3X9Cr/61RpTZIF5\n6obcnqDfdVsOcLZIjLpXeoW3GQ7dakwe3gPwVvCEEDqNzTPosxKNCUKlzVasRECQ\n-----END RSA PRIVATE KEY-----\n"},
		},
		{
			name:  "one line - newlines",
			input: `SUPERTOKENS_APPLE_SECRET_PRIVATE_KEY=-----BEGIN PRIVATE KEY-----\nMIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgu8gXs+XYkqXD6Ala9Sf/iJXzhbwcoG5dMh1OonpdJUmgCgYIKoZIzj0DAQehRANCAASfrvlFbFCYqn3I2zeknYXLwtH30JuOKestDbSfZYxZNMqhF/OzdZFTV0zc5u5s3eN+oCWbnvl0hM+9IW0UlkdA\n-----END PRIVATE KEY-----`,
			want:  []string{"-----BEGIN PRIVATE KEY-----\nMIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgu8gXs+XYkqXD6Ala9Sf/iJXzhbwcoG5dMh1OonpdJUmgCgYIKoZIzj0DAQehRANCAASfrvlFbFCYqn3I2zeknYXLwtH30JuOKestDbSfZYxZNMqhF/OzdZFTV0zc5u5s3eN+oCWbnvl0hM+9IW0UlkdA\n-----END PRIVATE KEY-----\n"},
		},
		{
			// https://github.com/trufflesecurity/trufflehog/issues/2338
			name:  "one line - spaces",
			input: `private_key=-----BEGIN RSA PRIVATE KEY----- MIICWQIBAAKBgHsSuRPLMDrxcwMB9P6ubGFGmlSvHvSXq2kfwycrcEKf/TCctShz A2HYo2IWed8n1rqazlESHnhNmCWlFWIMMFWagZyDBy9yy71MhWISvoTuQVyCx/z3 q1v171fy+Ds5smKwZ8wK3bgwBTR7BTKfYNmearDZvPJgwK0jsYEJDZ/DAgElAoGA MeT+7FlK53akP31VfAGF4j83pcp0VVI+kmbSk1bMpWN0e33M5uKE1KPvNZpowkCV UpHJQ3YMWkj4ffbRUUM2L/jQmKkICf7vynIdq5cj+lF6lNXSzwq6pVR6/octdeKS /70DuGcVG+LiRTu2mRb6mPY9bIJIvcgenXajnVanx9UCQQDRwf6oyU/EH4x+kw/X QZi/RebtDPD1yIQuhVG8B1xkPxBsAywTwVDL7DSZ1BsbWJcl5HcXt/q0n/3NZ62X Rr1VAkEAljSLsMOk5H7XCctEk3mCu1WgDtUvb/RRCBiBT+cic14OpVtytJMAeLeq cAhIj54ef4hQPGKbAsQZ3E/X4EsotwJAa7alXZfPA9jZcW4c5Ciai7wcoz3/Mhrc F+OYrKnVf5YBg5LtHua6yZT4aqswg6oIbWd7bQty5yG5rqrcmcphOQJAHGrOUd/T FnjckyZ0wfRk11VjeG2Fg+IdKwuOFgkiMYB/T7da4+R1tfk7666KRK82M82uUJ0I kdISuvpZRhwOnwJBAI34lnrN4bNcUVB5kAXT9huyH8tJomNdsJOufS3vCi5tKaqK Ic3jMIwtyuXsn4NhJNUFlgfPL70CPtb3x/eePqw= -----END RSA PRIVATE KEY-----`,
			want:  []string{"-----BEGIN RSA PRIVATE KEY-----\nMIICWQIBAAKBgHsSuRPLMDrxcwMB9P6ubGFGmlSvHvSXq2kfwycrcEKf/TCctShz\nA2HYo2IWed8n1rqazlESHnhNmCWlFWIMMFWagZyDBy9yy71MhWISvoTuQVyCx/z3\nq1v171fy+Ds5smKwZ8wK3bgwBTR7BTKfYNmearDZvPJgwK0jsYEJDZ/DAgElAoGA\nMeT+7FlK53akP31VfAGF4j83pcp0VVI+kmbSk1bMpWN0e33M5uKE1KPvNZpowkCV\nUpHJQ3YMWkj4ffbRUUM2L/jQmKkICf7vynIdq5cj+lF6lNXSzwq6pVR6/octdeKS\n/70DuGcVG+LiRTu2mRb6mPY9bIJIvcgenXajnVanx9UCQQDRwf6oyU/EH4x+kw/X\nQZi/RebtDPD1yIQuhVG8B1xkPxBsAywTwVDL7DSZ1BsbWJcl5HcXt/q0n/3NZ62X\nRr1VAkEAljSLsMOk5H7XCctEk3mCu1WgDtUvb/RRCBiBT+cic14OpVtytJMAeLeq\ncAhIj54ef4hQPGKbAsQZ3E/X4EsotwJAa7alXZfPA9jZcW4c5Ciai7wcoz3/Mhrc\nF+OYrKnVf5YBg5LtHua6yZT4aqswg6oIbWd7bQty5yG5rqrcmcphOQJAHGrOUd/T\nFnjckyZ0wfRk11VjeG2Fg+IdKwuOFgkiMYB/T7da4+R1tfk7666KRK82M82uUJ0I\nkdISuvpZRhwOnwJBAI34lnrN4bNcUVB5kAXT9huyH8tJomNdsJOufS3vCi5tKaqK\nIc3jMIwtyuXsn4NhJNUFlgfPL70CPtb3x/eePqw=\n-----END RSA PRIVATE KEY-----\n"},
		},
		{
			name:  "one line - encrypted",
			input: `    #             "privateKey": "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFDjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQIGepgN2Ze6asCAggA\nMBQGCCqGSIb3DQMHBAgVLnyjsNLu6ASCBMhSvz/EMaBaxfgi9Zs6RCKyEZWAQo34\nPGcdiiu1ebD7yxAQO88tV6ZJOpKJDxQDTLVB0GsPFJsmtuViSFWPxR5bHrfvL2Q/\nCcBB1HIgMByYPRf82Pg28shushae1Cn24vGmpgaLSPJ4skcF2kdLXirpKQTdUmYj\nAE1AYVPwd9r+0rsEhxaOVUr1MGBl9Af/muT/WxhIOAX/bhkeI9l6XIgRWukwjZhR\n9/CuIoOfxpsOHDcqN3lf6pB+bmTzlzVPith+WgjFEZndz63cvifha5AoErFWVZ30\nwHlWZxYgLPoyt5cI0TmTdS95DABuxu9N8aTMNYMLNx/cR+uLDpwBEnnnjNM195Li\nqur2CcP6cPg9f5AyOyIQSGrj93juN4usMDiArvaUUteBVhepUeu3Z7OrmkSf89Y9\nkMSRt+ZqXmZMIlBi3RoVD0rV4pQiH8D/NzEYH8aSrkSJwCf3fnOE39mXVg3gR9+P\n1KKuAl+oxSN916ZfOOu1Kd7LizdC7HDKDD1mnSkTr7Di+ubJ+ox4ZQcOSWUmrJu5\nMgCl1Bitgcybu5gnjO10Vo17UwE3TjzsbIyCgHw4ArMNewliVcUZRgSp2bWAvCIo\ntvZxJ/sTYiUulK5cm6VAdtYopQOo3R2N4zpV8wK6ymemx019N1OsyuqQDFmUMFlg\nAlZrI74Dkhba0JyuKe+SYQn9cqLIgYwBgUPCrQQwwoG8i/mhmBXf8T5NTyIwso03\niluof5g76f4rhJBC6/SFVR1NBS96Hsl7EjNxkR27Elx0g1tlSM0ilJhevwAQT2MM\n23Ux+CxiBOS2UzRyhx4fu91wsGLBFKdevlr43n2+PDb16baK3D8JCelxWLys/PZp\n5YzShdY35SDUM2u8/2Sc1W/RXAtUu9Az4QO2pB/xoUrFvQooM7VhlbKdWsve7u5b\nZDYhsZ/wYuAG2ixQodx6B75F+fG2TmU7LG1UWkyKtKL25FQvPGmcbvg/KExb2i5H\naPvwoDVhM6b3UNgPM9dSQKnTK8YjyVluSP86Mk2X8FYpzgHpKf+HCFEFPcLUOvE/\nUnteSGkRnebHmPFvTSna95b9ts7M6o2lW8auszt/Rc7CHlD9Ex/X6ed3ViSUKDQW\nDmmJbkMBUmcVYDWG7o2GPrJIhLJ96Jcp+YqrXZ5zuxCWw2gFqnId9WZMku1AUvsz\n7ty8smSMZarXbPgPM2Bccf1Plw4q739HKS5SrenrKo5UIuZukilyXD14Bq3mfJ55\n3Z01igk/FnaZzed+h8ciKMM6hyt5H7YszgcnHnpfF24yWMAZzO7edo0yH+RwJPT4\ndLbBVq9NbZAms4p05osnohly/BIkImKyZifayNAmdAObmW50v5MzNvssjMJrfHef\n4i9QXG/ACRYtuAAFWQdus/LdtcnxMY0TVIqm9YQXGThB9If0x2IFxsu+fH384T2C\nDPRdQ1s7+7Llb5dluoXsXNd9IJHh34/hLcgK7ftHpanETwNG3Bfd0f/juPvpPTOf\nUcgG3bDpu+a2hwUgvWlrYfqCvFCZKH+/CX2iSpmafjnQwD2EDb7EUdhd9Gb3c+dv\nfBW8dVLRFWtSfUF6gyNCnBiEbsNuyDQ7CnluIJHrDH9ilZ/d7yQZOQKeA9JFTM0x\nrYA=\n-----END ENCRYPTED PRIVATE KEY-----\n",`,
			want:  []string{"-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFDjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQIGepgN2Ze6asCAggA\nMBQGCCqGSIb3DQMHBAgVLnyjsNLu6ASCBMhSvz/EMaBaxfgi9Zs6RCKyEZWAQo34\nPGcdiiu1ebD7yxAQO88tV6ZJOpKJDxQDTLVB0GsPFJsmtuViSFWPxR5bHrfvL2Q/\nCcBB1HIgMByYPRf82Pg28shushae1Cn24vGmpgaLSPJ4skcF2kdLXirpKQTdUmYj\nAE1AYVPwd9r+0rsEhxaOVUr1MGBl9Af/muT/WxhIOAX/bhkeI9l6XIgRWukwjZhR\n9/CuIoOfxpsOHDcqN3lf6pB+bmTzlzVPith+WgjFEZndz63cvifha5AoErFWVZ30\nwHlWZxYgLPoyt5cI0TmTdS95DABuxu9N8aTMNYMLNx/cR+uLDpwBEnnnjNM195Li\nqur2CcP6cPg9f5AyOyIQSGrj93juN4usMDiArvaUUteBVhepUeu3Z7OrmkSf89Y9\nkMSRt+ZqXmZMIlBi3RoVD0rV4pQiH8D/NzEYH8aSrkSJwCf3fnOE39mXVg3gR9+P\n1KKuAl+oxSN916ZfOOu1Kd7LizdC7HDKDD1mnSkTr7Di+ubJ+ox4ZQcOSWUmrJu5\nMgCl1Bitgcybu5gnjO10Vo17UwE3TjzsbIyCgHw4ArMNewliVcUZRgSp2bWAvCIo\ntvZxJ/sTYiUulK5cm6VAdtYopQOo3R2N4zpV8wK6ymemx019N1OsyuqQDFmUMFlg\nAlZrI74Dkhba0JyuKe+SYQn9cqLIgYwBgUPCrQQwwoG8i/mhmBXf8T5NTyIwso03\niluof5g76f4rhJBC6/SFVR1NBS96Hsl7EjNxkR27Elx0g1tlSM0ilJhevwAQT2MM\n23Ux+CxiBOS2UzRyhx4fu91wsGLBFKdevlr43n2+PDb16baK3D8JCelxWLys/PZp\n5YzShdY35SDUM2u8/2Sc1W/RXAtUu9Az4QO2pB/xoUrFvQooM7VhlbKdWsve7u5b\nZDYhsZ/wYuAG2ixQodx6B75F+fG2TmU7LG1UWkyKtKL25FQvPGmcbvg/KExb2i5H\naPvwoDVhM6b3UNgPM9dSQKnTK8YjyVluSP86Mk2X8FYpzgHpKf+HCFEFPcLUOvE/\nUnteSGkRnebHmPFvTSna95b9ts7M6o2lW8auszt/Rc7CHlD9Ex/X6ed3ViSUKDQW\nDmmJbkMBUmcVYDWG7o2GPrJIhLJ96Jcp+YqrXZ5zuxCWw2gFqnId9WZMku1AUvsz\n7ty8smSMZarXbPgPM2Bccf1Plw4q739HKS5SrenrKo5UIuZukilyXD14Bq3mfJ55\n3Z01igk/FnaZzed+h8ciKMM6hyt5H7YszgcnHnpfF24yWMAZzO7edo0yH+RwJPT4\ndLbBVq9NbZAms4p05osnohly/BIkImKyZifayNAmdAObmW50v5MzNvssjMJrfHef\n4i9QXG/ACRYtuAAFWQdus/LdtcnxMY0TVIqm9YQXGThB9If0x2IFxsu+fH384T2C\nDPRdQ1s7+7Llb5dluoXsXNd9IJHh34/hLcgK7ftHpanETwNG3Bfd0f/juPvpPTOf\nUcgG3bDpu+a2hwUgvWlrYfqCvFCZKH+/CX2iSpmafjnQwD2EDb7EUdhd9Gb3c+dv\nfBW8dVLRFWtSfUF6gyNCnBiEbsNuyDQ7CnluIJHrDH9ilZ/d7yQZOQKeA9JFTM0x\nrYA=\n-----END ENCRYPTED PRIVATE KEY-----\n"},
		},
		{
			name: "one line - orphaned header",
			input: `# Should Match
# Should capture private key headers
-----BEGIN PGP PRIVATE KEY-----

# Should Match
# Should capture private key headers
-----BEGIN OPENSSH PRIVATE KEY-----\n0b3d576ba5a108c3b7374142bfd029920b3d576ba5a108c3b7374142bfd029920b3d576ba5a108c3b7374142bfd02992\n-----END OPENSSH PRIVATE KEY-----
`,
			want: []string{"-----BEGIN OPENSSH PRIVATE KEY-----\n0b3d576ba5a108c3b7374142bfd029920b3d576ba5a108c3b7374142bfd029920b3d576ba5a108c3b7374142bfd02992\n-----END OPENSSH PRIVATE KEY-----\n"},
		},

		// Invalid
		{
			name: "invalid - content",
			input: `        "jwt-auth": {
            "key": "user-key",
            "public_key": "-----BEGIN PUBLIC KEY-----\n……\n-----END PUBLIC KEY-----",
            "private_key": "-----BEGIN RSA PRIVATE KEY-----\n……\n-----END RSA PRIVATE KEY-----",
            "algorithm": "RS256"
        }`,
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

package privatekey

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
)

func TestNormalize(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr error
	}{
		// Valid
		{
			name: "empty",
			input: `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCXQ8X2JLjOMBJw
6hecwM7y71iLEn1GXgHxGpOyPtjPmbwQMvESsO8AbNbERYWoM3vN7I9KktBaSkFp
f+PdfnHSIZzfQ7VsYLsqEqgIz8XuCH1I6ktU5ILZiLC4XgISyw4JmbdfQrbXJjQP
Suf8rJxZzaFQTIhf8dJ+WyFB8DdQgEhxUCZhJnlkS36RjQ70J/4ZgL85Vbfz0M1h
bNjBx9Mmd5IaFEJWy7z9GkrrF9iNr9HARp/wQF4ONC/n275m/YkLa4xxwQsKxcTE
639EwXU2I/3ttu6H2YhH4Ut8YFPnhRwvgksrXmMaSRc2LPw5I0kiTUO1USISJJ4x
RNgWTqjrAgMBAAECggEAVurwo4FyV7gzwIIi00XPJLT3ceJL7dUy1HHrEG8gchnq
gHxlHdJhYyMnPVydcosyxp75r2YxJtCoSZDdRHbVvGLoGzpy0zW6FnDl8TpCh4aF
RxKp+rvbnFf5A9ew5U+cX1PelHRnT7V6EJeAOiaNKOUJnnR7oHX59/UxZQw9HJnX
3H4xUdRDmSS3BGKXEswbd7beQjqJtEIkbConfaw32yEod0w2MC0LI4miZ87/6Hsk
pyvfpeYxXp4z3BTvFBbf/GEBFuozu63VWHayB9PDmEN/TlphoQpJQihdR2r1lz/H
I5QwVlFTDvUSFitNLu+FoaHOfgLprQndbojBXb+tcQKBgQDHCPyM4V7k97RvJgmB
ELgZiDYufDrjRLXvFzrrZ7ySU3N+nx3Gz/EhtgbHicDjnRVagHBIwi/QAfBJksCd
xcioY5k2OW+8PSTsfFZTAA6XwJp/LGfJik/JjvAVv5CnxBu9lYG4WiSBJFp59ojC
zTmfEuB4GPwrjQvzjlqaSpij9QKBgQDCjriwAB2UJIdlgK+DkryLqgim5I4cteB3
+juVKz+S8ufFmVvmIXkyDcpyy/26VLC6esy8dV0JoWc4EeitoJvQD1JVZ5+CBTY+
r9umx18oe2A/ZgcEf/A3Zd94jM1MwriF6YC+eIOhwhpi7T1xTLf3hc9B0OJ5B1mA
vob9rGDtXwKBgD4rkW+UCictNIAvenKFPWxEPuBgT6ij0sx/DhlwCtgOFxprK0rp
syFbkVyMq+KtM3lUez5O4c5wfJUOsPnXSOlISxhD8qHy23C/GdvNPcGrGNc2kKjE
ek20R0wTzWSJ/jxG0gE6rwJjz5sfJfLjVd9ZbyI0c7hK03vdcHGXcXxtAoGAeGHl
BwnbQ3niyTx53VijD2wTVGjhQgSLstEDowYSnTNtk8eTpG6b1gvQc32jLnMOsyQe
oJGiEr5q5re2GBDjuDZyxGOMv9/Hs7wOlkCQsbS9Vh0kRHWBRlXjk2zT7yYhFMLp
pXFeSW2X9BRFS2CkCCUkm93K9AZHLDE3x6ishNMCgYEAsDsUCzGhI49Aqe+CMP2l
WPZl7SEMYS5AtdC5sLtbLYBl8+rMXVGL2opKXqVFYBYkqMJiHGdX3Ub6XSVKLYkN
vm4PWmlQS24ZT+jlUl4jk6JU6SAlM/o6ixZl5KNR7yQm6zN2O/RHDeYm0urUQ9tF
9dux7LbIFeOoJmoDTWG2+fI=
-----END PRIVATE KEY-----`,
			want: "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCXQ8X2JLjOMBJw\n6hecwM7y71iLEn1GXgHxGpOyPtjPmbwQMvESsO8AbNbERYWoM3vN7I9KktBaSkFp\nf+PdfnHSIZzfQ7VsYLsqEqgIz8XuCH1I6ktU5ILZiLC4XgISyw4JmbdfQrbXJjQP\nSuf8rJxZzaFQTIhf8dJ+WyFB8DdQgEhxUCZhJnlkS36RjQ70J/4ZgL85Vbfz0M1h\nbNjBx9Mmd5IaFEJWy7z9GkrrF9iNr9HARp/wQF4ONC/n275m/YkLa4xxwQsKxcTE\n639EwXU2I/3ttu6H2YhH4Ut8YFPnhRwvgksrXmMaSRc2LPw5I0kiTUO1USISJJ4x\nRNgWTqjrAgMBAAECggEAVurwo4FyV7gzwIIi00XPJLT3ceJL7dUy1HHrEG8gchnq\ngHxlHdJhYyMnPVydcosyxp75r2YxJtCoSZDdRHbVvGLoGzpy0zW6FnDl8TpCh4aF\nRxKp+rvbnFf5A9ew5U+cX1PelHRnT7V6EJeAOiaNKOUJnnR7oHX59/UxZQw9HJnX\n3H4xUdRDmSS3BGKXEswbd7beQjqJtEIkbConfaw32yEod0w2MC0LI4miZ87/6Hsk\npyvfpeYxXp4z3BTvFBbf/GEBFuozu63VWHayB9PDmEN/TlphoQpJQihdR2r1lz/H\nI5QwVlFTDvUSFitNLu+FoaHOfgLprQndbojBXb+tcQKBgQDHCPyM4V7k97RvJgmB\nELgZiDYufDrjRLXvFzrrZ7ySU3N+nx3Gz/EhtgbHicDjnRVagHBIwi/QAfBJksCd\nxcioY5k2OW+8PSTsfFZTAA6XwJp/LGfJik/JjvAVv5CnxBu9lYG4WiSBJFp59ojC\nzTmfEuB4GPwrjQvzjlqaSpij9QKBgQDCjriwAB2UJIdlgK+DkryLqgim5I4cteB3\n+juVKz+S8ufFmVvmIXkyDcpyy/26VLC6esy8dV0JoWc4EeitoJvQD1JVZ5+CBTY+\nr9umx18oe2A/ZgcEf/A3Zd94jM1MwriF6YC+eIOhwhpi7T1xTLf3hc9B0OJ5B1mA\nvob9rGDtXwKBgD4rkW+UCictNIAvenKFPWxEPuBgT6ij0sx/DhlwCtgOFxprK0rp\nsyFbkVyMq+KtM3lUez5O4c5wfJUOsPnXSOlISxhD8qHy23C/GdvNPcGrGNc2kKjE\nek20R0wTzWSJ/jxG0gE6rwJjz5sfJfLjVd9ZbyI0c7hK03vdcHGXcXxtAoGAeGHl\nBwnbQ3niyTx53VijD2wTVGjhQgSLstEDowYSnTNtk8eTpG6b1gvQc32jLnMOsyQe\noJGiEr5q5re2GBDjuDZyxGOMv9/Hs7wOlkCQsbS9Vh0kRHWBRlXjk2zT7yYhFMLp\npXFeSW2X9BRFS2CkCCUkm93K9AZHLDE3x6ishNMCgYEAsDsUCzGhI49Aqe+CMP2l\nWPZl7SEMYS5AtdC5sLtbLYBl8+rMXVGL2opKXqVFYBYkqMJiHGdX3Ub6XSVKLYkN\nvm4PWmlQS24ZT+jlUl4jk6JU6SAlM/o6ixZl5KNR7yQm6zN2O/RHDeYm0urUQ9tF\n9dux7LbIFeOoJmoDTWG2+fI=\n-----END PRIVATE KEY-----\n",
		},

		// Invalid
		{
			name:    "invalid - no header",
			input:   ``,
			wantErr: errNoHeader,
		},
		{
			name: "invalid - content",
			input: `        "jwt-auth": {
            "key": "user-key",
            "public_key": "-----BEGIN PUBLIC KEY-----\n……\n-----END PUBLIC KEY-----",
            "private_key": "-----BEGIN RSA PRIVATE KEY-----\n……\n-----END RSA PRIVATE KEY-----",
            "algorithm": "RS256"
        }`,
			wantErr: errNoContent,
		},
		{
			name: "invalid - no content",
			input: `/* openssh private key file format */
#define MARK_BEGIN		"-----BEGIN OPENSSH PRIVATE KEY-----\n"
#define MARK_END		"-----END OPENSSH PRIVATE KEY-----\n"
#define MARK_BEGIN_LEN		(sizeof(MARK_BEGIN) - 1)
#define MARK_END_LEN		(sizeof(MARK_END) - 1)`,
			wantErr: errNoContent,
		},
		{
			// OpenSSH private key with the first line decoded with base64.
			name:    "invalid - base64 mangling",
			input:   string([]byte{45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 79, 80, 69, 78, 83, 83, 72, 32, 80, 82, 73, 86, 65, 84, 69, 32, 75, 69, 89, 45, 45, 45, 45, 45, 10, 111, 112, 101, 110, 115, 115, 104, 45, 107, 101, 121, 45, 118, 49, 0, 0, 0, 0, 4, 110, 111, 110, 101, 0, 0, 0, 4, 110, 111, 110, 101, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 23, 0, 0, 0, 7, 115, 115, 104, 45, 114, 10, 78, 104, 65, 65, 65, 65, 65, 119, 69, 65, 65, 81, 65, 65, 65, 81, 69, 65, 51, 43, 101, 112, 102, 43, 86, 71, 75, 111, 71, 80, 97, 65, 90, 88, 114, 102, 54, 83, 48, 99, 121, 117, 109, 81, 110, 100, 100, 107, 71, 66, 110, 86, 70, 88, 48, 65, 53, 101, 104, 51, 55, 82, 116, 76, 117, 103, 48, 113, 89, 53, 10, 116, 104, 120, 115, 66, 85, 98, 71, 71, 86, 114, 57, 109, 84, 100, 50, 81, 88, 119, 76, 117, 106, 66, 119, 89, 103, 53, 108, 49, 77, 80, 47, 70, 109, 103, 43, 53, 51, 49, 50, 90, 103, 120, 57, 112, 72, 109, 83, 43, 113, 75, 85, 76, 98, 97, 114, 48, 104, 108, 78, 103, 112, 116, 78, 69, 98, 43, 97, 78, 85, 10, 100, 51, 111, 57, 113, 103, 51, 97, 88, 113, 88, 109, 55, 43, 90, 110, 106, 65, 86, 48, 53, 101, 102, 47, 109, 120, 78, 82, 78, 50, 90, 118, 117, 69, 107, 119, 55, 99, 82, 112, 112, 84, 74, 99, 98, 66, 73, 43, 118, 70, 51, 108, 88, 117, 67, 88, 110, 88, 50, 107, 108, 68, 73, 57, 53, 71, 108, 50, 65, 87, 10, 51, 87, 72, 82, 116, 97, 110, 113, 76, 72, 90, 88, 117, 66, 107, 106, 106, 82, 66, 68, 75, 99, 55, 77, 85, 113, 47, 71, 80, 49, 104, 109, 76, 105, 65, 100, 57, 53, 100, 118, 85, 55, 102, 90, 106, 82, 108, 73, 69, 115, 80, 56, 52, 122, 71, 69, 73, 49, 70, 98, 48, 76, 47, 107, 109, 80, 72, 99, 79, 116, 10, 105, 86, 102, 72, 102, 116, 56, 67, 116, 109, 67, 57, 118, 54, 43, 57, 52, 74, 114, 79, 105, 80, 66, 66, 78, 83, 99, 86, 43, 100, 121, 114, 103, 65, 71, 80, 115, 100, 75, 100, 114, 47, 49, 118, 73, 112, 81, 109, 67, 78, 105, 73, 56, 115, 51, 80, 67, 105, 68, 56, 74, 55, 90, 105, 66, 97, 89, 109, 48, 73, 10, 56, 102, 113, 53, 71, 47, 113, 110, 85, 119, 65, 65, 65, 55, 103, 103, 119, 50, 100, 88, 73, 77, 78, 110, 86, 119, 65, 65, 65, 65, 100, 122, 99, 50, 103, 116, 99, 110, 78, 104, 65, 65, 65, 66, 65, 81, 68, 102, 53, 54, 108, 47, 53, 85, 89, 113, 103, 89, 57, 111, 66, 108, 101, 116, 47, 112, 76, 82, 122, 75, 10, 54, 90, 67, 100, 49, 50, 81, 89, 71, 100, 85, 86, 102, 81, 68, 108, 54, 72, 102, 116, 71, 48, 117, 54, 68, 83, 112, 106, 109, 50, 72, 71, 119, 70, 82, 115, 89, 90, 87, 118, 50, 90, 78, 51, 90, 66, 102, 65, 117, 54, 77, 72, 66, 105, 68, 109, 88, 85, 119, 47, 56, 87, 97, 68, 55, 110, 102, 88, 90, 109, 10, 68, 72, 50, 107, 101, 90, 76, 54, 111, 112, 81, 116, 116, 113, 118, 83, 71, 85, 50, 67, 109, 48, 48, 82, 118, 53, 111, 49, 82, 51, 101, 106, 50, 113, 68, 100, 112, 101, 112, 101, 98, 118, 53, 109, 101, 77, 66, 88, 84, 108, 53, 47, 43, 98, 69, 49, 69, 51, 90, 109, 43, 52, 83, 84, 68, 116, 120, 71, 109, 108, 10, 77, 108, 120, 115, 69, 106, 54, 56, 88, 101, 86, 101, 52, 74, 101, 100, 102, 97, 83, 85, 77, 106, 51, 107, 97, 88, 89, 66, 98, 100, 89, 100, 71, 49, 113, 101, 111, 115, 100, 108, 101, 52, 71, 83, 79, 78, 69, 69, 77, 112, 122, 115, 120, 83, 114, 56, 89, 47, 87, 71, 89, 117, 73, 66, 51, 51, 108, 50, 57, 84, 10, 116, 57, 109, 78, 71, 85, 103, 83, 119, 47, 122, 106, 77, 89, 81, 106, 85, 86, 118, 81, 118, 43, 83, 89, 56, 100, 119, 54, 50, 74, 86, 56, 100, 43, 51, 119, 75, 50, 89, 76, 50, 47, 114, 55, 51, 103, 109, 115, 54, 73, 56, 69, 69, 49, 74, 120, 88, 53, 51, 75, 117, 65, 65, 89, 43, 120, 48, 112, 50, 118, 10, 47, 87, 56, 105, 108, 67, 89, 73, 50, 73, 106, 121, 122, 99, 56, 75, 73, 80, 119, 110, 116, 109, 73, 70, 112, 105, 98, 81, 106, 120, 43, 114, 107, 98, 43, 113, 100, 84, 65, 65, 65, 65, 65, 119, 69, 65, 65, 81, 65, 65, 65, 81, 69, 65, 114, 87, 109, 53, 66, 52, 116, 70, 97, 115, 112, 112, 106, 85, 72, 77, 10, 83, 115, 65, 117, 97, 106, 116, 67, 120, 116, 105, 122, 73, 49, 72, 99, 49, 48, 69, 87, 53, 57, 99, 90, 77, 52, 118, 118, 85, 122, 69, 50, 102, 54, 43, 113, 90, 118, 100, 103, 87, 106, 51, 85, 85, 47, 76, 55, 69, 116, 50, 51, 119, 48, 81, 86, 117, 83, 67, 110, 67, 101, 114, 111, 120, 51, 55, 57, 90, 66, 10, 100, 100, 69, 79, 70, 70, 65, 65, 105, 81, 106, 119, 66, 120, 54, 53, 104, 98, 100, 52, 82, 82, 85, 121, 109, 120, 116, 73, 81, 102, 106, 113, 49, 56, 43, 43, 76, 99, 77, 74, 87, 49, 110, 98, 86, 81, 55, 99, 54, 57, 84, 104, 81, 98, 116, 65, 76, 73, 103, 103, 109, 98, 83, 43, 90, 69, 47, 56, 71, 120, 10, 106, 107, 119, 109, 73, 114, 67, 72, 48, 87, 119, 56, 84, 108, 112, 115, 80, 101, 43, 109, 78, 72, 117, 121, 78, 107, 55, 85, 69, 90, 111, 88, 76, 109, 50, 50, 108, 78, 76, 113, 113, 53, 113, 107, 73, 76, 53, 74, 103, 84, 54, 77, 50, 105, 78, 74, 112, 77, 79, 74, 121, 57, 47, 67, 75, 105, 54, 107, 79, 52, 10, 74, 80, 117, 86, 119, 106, 100, 71, 52, 67, 53, 112, 66, 80, 97, 77, 78, 51, 75, 74, 49, 73, 118, 65, 108, 83, 108, 76, 71, 78, 97, 88, 110, 102, 88, 99, 110, 56, 53, 103, 87, 102, 115, 67, 106, 115, 90, 109, 72, 51, 108, 105, 101, 121, 50, 78, 74, 97, 109, 113, 112, 47, 119, 56, 51, 66, 114, 75, 85, 103, 10, 89, 90, 118, 77, 82, 50, 113, 101, 87, 90, 97, 75, 107, 70, 84, 97, 104, 112, 122, 78, 53, 75, 82, 75, 49, 66, 70, 101, 66, 51, 55, 79, 48, 80, 56, 52, 68, 122, 104, 49, 98, 105, 68, 88, 56, 81, 65, 65, 65, 73, 69, 65, 105, 87, 88, 87, 56, 101, 80, 89, 70, 119, 76, 112, 97, 50, 109, 70, 73, 104, 10, 86, 118, 82, 84, 100, 99, 114, 78, 55, 48, 114, 86, 75, 53, 101, 87, 86, 97, 76, 51, 112, 121, 83, 52, 118, 71, 65, 53, 54, 74, 105, 120, 113, 56, 54, 100, 72, 118, 101, 79, 110, 98, 83, 89, 43, 105, 78, 98, 49, 106, 81, 105, 100, 116, 88, 99, 56, 83, 87, 85, 116, 50, 119, 116, 72, 113, 90, 51, 50, 104, 10, 76, 106, 105, 57, 47, 104, 77, 83, 75, 113, 101, 57, 83, 69, 80, 51, 120, 118, 68, 82, 68, 109, 85, 74, 113, 115, 86, 119, 48, 121, 83, 121, 114, 70, 114, 122, 109, 52, 49, 54, 48, 81, 89, 54, 82, 75, 85, 51, 67, 73, 81, 67, 86, 70, 115, 108, 77, 90, 57, 102, 120, 109, 114, 102, 90, 47, 104, 120, 111, 85, 10, 48, 88, 51, 70, 86, 115, 120, 109, 67, 52, 43, 107, 119, 65, 65, 65, 67, 66, 65, 80, 79, 99, 49, 89, 69, 82, 112, 86, 54, 80, 106, 65, 78, 66, 114, 71, 82, 43, 49, 111, 49, 82, 67, 100, 65, 67, 98, 109, 53, 109, 121, 99, 52, 50, 81, 122, 83, 78, 73, 97, 79, 90, 109, 103, 114, 89, 115, 43, 71, 116, 10, 55, 43, 69, 99, 111, 113, 83, 100, 98, 74, 122, 72, 74, 78, 67, 78, 81, 102, 70, 43, 65, 43, 118, 106, 98, 73, 107, 70, 105, 117, 90, 113, 113, 47, 53, 119, 119, 114, 53, 57, 113, 88, 120, 53, 79, 65, 108, 105, 106, 76, 66, 47, 121, 119, 119, 75, 109, 84, 87, 113, 54, 108, 112, 47, 47, 90, 120, 110, 121, 43, 10, 107, 97, 51, 115, 73, 71, 78, 79, 49, 52, 101, 81, 118, 109, 120, 78, 68, 110, 108, 76, 76, 43, 82, 73, 90, 108, 101, 67, 84, 69, 75, 66, 88, 83, 87, 54, 67, 90, 104, 114, 43, 117, 72, 77, 90, 70, 75, 75, 77, 116, 65, 65, 65, 65, 103, 81, 68, 114, 83, 107, 109, 43, 76, 98, 73, 76, 66, 55, 72, 57, 10, 106, 120, 69, 66, 90, 76, 104, 118, 53, 51, 97, 65, 110, 52, 117, 56, 49, 107, 70, 75, 81, 79, 74, 55, 80, 122, 122, 112, 66, 71, 83, 111, 68, 49, 50, 105, 55, 111, 73, 74, 117, 53, 115, 105, 83, 68, 53, 69, 75, 68, 78, 86, 69, 114, 43, 83, 118, 67, 102, 48, 73, 83, 85, 51, 66, 117, 77, 112, 122, 108, 10, 116, 51, 89, 114, 80, 114, 72, 82, 104, 101, 79, 70, 104, 110, 53, 101, 51, 106, 48, 101, 47, 47, 122, 66, 56, 114, 66, 67, 48, 68, 71, 66, 52, 67, 116, 84, 68, 100, 101, 104, 55, 114, 79, 88, 85, 76, 52, 75, 48, 112, 122, 43, 56, 119, 69, 112, 78, 107, 86, 54, 50, 83, 87, 120, 104, 67, 54, 78, 82, 87, 10, 73, 55, 57, 74, 104, 116, 71, 107, 104, 43, 71, 116, 99, 110, 107, 69, 102, 119, 65, 65, 65, 65, 65, 66, 10, 45, 45, 45, 45, 45, 69, 78, 68, 32, 79, 80, 69, 78, 83, 83, 72, 32, 80, 82, 73, 86, 65, 84, 69, 32, 75, 69, 89, 45, 45, 45, 45, 45}),
			wantErr: errBase64,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if len(test.input) == 0 {
				t.Skip()
				return
			}

			match := keyPat.Find([]byte(test.input))
			if match == nil {
				t.Errorf(`keyPat.FindString(%s) => "%s"`, test.input, test.name)
				return
			}

			actual, err := normalizeMatch(match)
			if err != nil {
				if test.wantErr != nil {
					assert.EqualError(t, err, test.wantErr.Error())
				} else {
					t.Errorf("received unexpected error: %v", err)
					return
				}
			}
			if actual == "" {
				if test.want != "" {
					t.Errorf("expected: %v, got no result", test.want)
				}
				return
			}

			if diff := cmp.Diff(test.want, actual); diff != "" {
				t.Errorf("%s diff: (-want +got)\n%s", test.name, diff)
			}
		})
	}
}

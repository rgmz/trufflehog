package privatekey

import (
	"bytes"
	"errors"
	"regexp"
	"strings"
)

var (
	// Common errors
	errNoHeader  = errors.New("no header line found")
	errNoContent = errors.New("no content line(s) found")
	errNoFooter  = errors.New("no footer line found")

	// Workaround to base64-decoder malforming keys.
	// https://archive.ph/qE2C5
	errBase64      = errors.New("key malformed by base64 decoder")
	b64MagicString = []byte("openssh-key-v1\u0000\u0000\u0000\u0000\u0004none")
)

// normalizeMatch attempts to extract PEM content from surrounding noise, such as quotes.
//
// It seems there are five sections: (1) header, (2) content header [optional],
// (3) content body, (4) content footer [optional], and (5) footer.
// ```
// (1) -----BEGIN RSA PRIVATE KEY-----\n
// (2) Proc-Type: 4,ENCRYPTED\n
// \n
// (3) MIIEowIBAAKCAQEAm+4biWr5sqOihV7T5poaMteQBNj2VKzGm4g+jG0NVXe4XSjk\n
// (3) /70DuGcVG+LiRTu2mRb6mPY9bIJIvcgenXajnVanx9UCQQDRwf6oyU/EH4x+kw/X\n
// (4) L70CPtb3x/eePqw=\n
// (5) -----END RSA PRIVATE KEY-----\n
// ```
func normalizeMatch(input []byte) (string, error) {
	var (
		lines []string

		headerEndIdx   int
		footerStartIdx int
		footerEndIdx   int
	)

	// Parse the header and footer first.
	// This validates that the input is valid & provides a boundary for content.
	if match := headerPat.FindSubmatchIndex(input); match != nil {
		headerEndIdx = match[3]
		lines = append(lines, string(input[match[2]:match[3]]))
	} else {
		return "", errNoHeader
	}

	if match := footerPat.FindIndex(input); match != nil {
		footerStartIdx = match[0]
		footerEndIdx = match[1]

		// Skip incomplete matches.
		// i.e., a header with no content or footer.
		if idx := bytes.Index(input[headerEndIdx:footerStartIdx], []byte("-----BEGIN")); idx != -1 {
			return normalizeMatch(input[headerEndIdx+idx : footerEndIdx])
		}
	} else {
		return "", errNoFooter
	}

	// Parse the content.
	var (
		contentBytes = input[headerEndIdx:footerStartIdx]
		lastIdx      int
		l            []string
	)
	if len(contentBytes) < 64 {
		return "", errNoContent
	}
	// Extract the headers, if they exist.
	if l, lastIdx = getContentHeaderLines(contentBytes); l != nil {
		lines = append(lines, l...)
		contentBytes = contentBytes[lastIdx:]
	}

	// Sanity check: has the first line been mangled by bas64 decoding?
	if bytes.Contains(contentBytes[:64], b64MagicString) {
		return "", errBase64
	}
	// Extract the body.
	if l, lastIdx = getContentLines(contentBytes); l != nil {
		lines = append(lines, l...)
	} else {
		return "", errNoContent
	}

	// Extract the footer, if it exists.
	if l := getContentFooterLine(contentBytes[lastIdx:]); l != "" {
		lines = append(lines, l)
	}

	// Finally, append the PEM footer.
	lines = append(lines, string(input[footerStartIdx:footerEndIdx])+"\n")
	return strings.Join(lines, "\n"), nil
}

var (
	headerPat        = regexp.MustCompile(`^(-----BEGIN[ \w-]{0,100}PRIVATE KEY(?: BLOCK)?-----).*(?:\\r|\\n|[ \t\r\n]){1,5}`)
	contentHeaderPat = regexp.MustCompile(`(?:[ \t\r\n"'\x60]|\\+r|\\+n)?([A-Z][a-zA-Z]{2,10}(?:-[A-Z][a-zA-Z]{2,10})+:[ \t].+?)(?:[ \t\r\n"'\x60]|\\+r|\\+n)`)
	// contentPat       = regexp.MustCompile(`(?:\\r|\\n|[ \t\r\n]){0,5}.*?([a-zA-Z0-9/+]{64,}).*?(?:\\r|\\n|[ \t\r\n]){1,5}`)
	contentPat = regexp.MustCompile(`(?:\A|[ \t\r\n"'\x60]|\\+r|\\+n)?([a-zA-Z0-9/+]{64,})(?:[ \t\r\n"'\x60]|\\+r|\\+n)`)
	// contentFooterPat = regexp.MustCompile(`(?:\\r|\\n|[ \t\r\n]){0,5}.*?((?:[a-zA-Z0-9/+]{4})+|(?:|[a-zA-Z0-9/+]{4})*(?:[a-zA-Z0-9/+]{3}=|[a-zA-Z0-9/+]{2}==|[a-zA-Z0-9/+]===?)).*?(?:\\r|\\n|[ \t\r\n]){1,5}`)
	contentFooterPat = regexp.MustCompile(`(?:\A|[ \t\r\n"'\x60]|\\+r|\\+n)((?:[a-zA-Z0-9/+]{4})*[a-zA-Z0-9][a-zA-Z0-9/+]+={0,3})(?:[ \t\r\n"'\x60]|\\+r|\\+n|\z)`)
	footerPat        = regexp.MustCompile(`-----[ \t]{0,5}END[ \w-]{0,100}PRIVATE KEY(?: BLOCK)??[ \t]{0,5}-----$`)
)

// `\nProc-Type: 4,ENCRYPTED\n`
func getContentHeaderLines(data []byte) ([]string, int) {
	var (
		lastIdx = 0
		match   []int
		lines   []string
	)
	for lastIdx < len(data) {
		if match = contentHeaderPat.FindSubmatchIndex(data[lastIdx:]); match == nil {
			break
		}

		// Adjust match indices relative to the full input
		start := lastIdx + match[2]
		end := lastIdx + match[3]

		lines = append(lines, string(data[start:end]))
		lastIdx = lastIdx + match[1]
	}
	return lines, lastIdx
}

// `/70DuGcVG+LiRTu2mRb6mPY9bIJIvcgenXajnVanx9UCQQDRwf6oyU/EH4x+kw/X\n`
func getContentLines(data []byte) ([]string, int) {
	var (
		lines   []string
		lastIdx = 0
		match   []int
	)
	for lastIdx < len(data) {
		if match = contentPat.FindSubmatchIndex(data[lastIdx:]); match == nil {
			break
		}

		// Adjust match indices relative to the full input
		start := lastIdx + match[2]
		end := lastIdx + match[3]

		lines = append(lines, string(data[start:end]))
		lastIdx = lastIdx + match[1]
	}
	return lines, lastIdx
}

// `\nIc3jMIwtyuXsn4NhJNUFlgfPL70CPtb3x/eePqw=\n`
func getContentFooterLine(data []byte) string {
	if loc := contentFooterPat.FindSubmatchIndex(data); loc != nil {
		return string(data[loc[2]:loc[3]])
	}
	return ""
}

func NormalizeOld(in string) string {
	in = strings.ReplaceAll(in, `"`, "")
	in = strings.ReplaceAll(in, `'`, "")
	in = strings.ReplaceAll(in, "\t", "")
	in = strings.ReplaceAll(in, `\t`, "")
	in = strings.ReplaceAll(in, `\\t`, "")
	in = strings.ReplaceAll(in, `\n`, "\n")
	in = strings.ReplaceAll(in, `\\r\\n`, "\n")
	in = strings.ReplaceAll(in, `\r\n`, "\n")
	in = strings.ReplaceAll(in, "\r\n", "\n")
	in = strings.ReplaceAll(in, `\\r`, "\n")
	in = strings.ReplaceAll(in, "\r", "\n")
	in = strings.ReplaceAll(in, `\r`, "\n")
	in = strings.ReplaceAll(in, `\\n`, "\n")
	in = strings.ReplaceAll(in, `\n\n`, "\n")
	in = strings.ReplaceAll(in, "\n\n", "\n")
	in = strings.ReplaceAll(in, `\\`, "\n")

	cleaned := strings.Builder{}
	parts := strings.Split(in, "\n")
	for _, line := range parts {
		cleaned.WriteString(strings.TrimSpace(line) + "\n")
	}
	return cleaned.String()
}

package decoders

import (
	"bytes"
	"regexp"
	"sync"

	ahocorasick "github.com/BobuSumisu/aho-corasick"
	"github.com/go-logr/logr"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// Percent decodes characters that are percent encoded.
// https://developer.mozilla.org/en-US/docs/Glossary/Percent-encoding
// https://en.wikipedia.org/wiki/Percent-encoding
type Percent struct{}

var (
	_ Decoder = (*Percent)(nil)

	percentOnce           sync.Once
	percentTrie           *ahocorasick.Trie
	percentEncodingToChar = map[string]string{}
)

func init() {
	// Use Aho-Corasick to pre-filter potential matches.
	percentOnce.Do(func() {
		specialChars := map[string][]string{
			"!": {"%21"},
			"#": {"%23"},
			"$": {"%24"},
			"%": {"%25"},
			"&": {"%26"},
			"'": {"%27"},
			"(": {"%28"},
			")": {"%29"},
			"*": {"%2A", "%2a"},
			"+": {"%2B", "%2b"},
			",": {"%2C", "%2c"},
			"/": {"%2F", "%2f"},
			":": {"%3A", "%3a"},
			";": {"%3B", "%3b"},
			"=": {"%3D", "%3d"},
			"?": {"%3F", "%3f"},
			"@": {"%40"},
			"[": {"%5B", "%5b"},
			"]": {"%5D", "%5d"},
			" ": {"%20"}, // Space should also be percent encoded
			`"`: {"%22"}, // Double quote
			"<": {"%3C", "%3c"},
			">": {"%3E", "%3e"},
			`\`: {"%5C", "%5c"},
			"^": {"%5E", "%5e"},
			"`": {"%60"},
			"{": {"%7B", "%7b"},
			"|": {"%7C", "%7c"},
			"}": {"%7D", "%7d"},
		}

		var keywords []string
		for char, encodings := range specialChars {
			for _, encoding := range encodings {
				percentEncodingToChar[encoding] = char
				keywords = append(keywords, encoding)
			}
		}
		percentTrie = ahocorasick.NewTrieBuilder().AddStrings(keywords).Build()
	})
}

func (d *Percent) Type() detectorspb.DecoderType {
	return detectorspb.DecoderType_PERCENT
}

func (d *Percent) FromChunk(ctx context.Context, chunk *sources.Chunk) *DecodableChunk {
	if chunk == nil || len(chunk.Data) == 0 {
		return nil
	} else if m := percentTrie.MatchFirst(chunk.Data); m == nil {
		return nil
	}

	var (
		logger = ctx.Logger().WithName("decoders.percent")
		// Necessary to avoid data races.
		chunkData = bytes.Clone(chunk.Data)
		matched   = false
	)
	if percentEncodedPat.Match(chunkData) {
		matched = true
		chunkData = decoderPercent(logger, chunkData)
	}

	if matched {
		return &DecodableChunk{
			DecoderType: d.Type(),
			Chunk: &sources.Chunk{
				Data:           chunkData,
				SourceName:     chunk.SourceName,
				SourceID:       chunk.SourceID,
				JobID:          chunk.JobID,
				SecretID:       chunk.SecretID,
				SourceMetadata: chunk.SourceMetadata,
				SourceType:     chunk.SourceType,
				Verify:         chunk.Verify,
			},
		}
	} else {
		return nil
	}
}

// `!` = `%21`
var percentEncodedPat = regexp.MustCompile(`(?i)%[a-f0-9]{2}`)

func decoderPercent(logger logr.Logger, input []byte) []byte {
	var (
		decoded   = make([]byte, 0, len(input))
		lastIndex = 0
	)

	for _, match := range percentEncodedPat.FindAllSubmatchIndex(input, -1) {
		startIndex := match[0]
		endIndex := match[1]

		// Copy the part of the input until the start of the entity
		decoded = append(decoded, input[lastIndex:startIndex]...)

		// Append the decoded byte
		char, ok := percentEncodingToChar[string(input[startIndex:endIndex])]
		if !ok {
			// logger.Error(fmt.Errorf("unrecognized encoding"), "Unable to decode percent entity", "match", encoded)
			continue
		}
		decoded = append(decoded, []byte(char)...)
		lastIndex = endIndex
	}

	// Append the remaining part of the input
	decoded = append(decoded, input[lastIndex:]...)

	return decoded
}

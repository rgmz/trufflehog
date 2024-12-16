package detectors

import (
	aCtx "context"
	"log"

	regexp "github.com/wasilibs/go-re2"
	"golang.org/x/exp/maps"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

type SinglePartDetector interface {
	Type() detectorspb.DetectorType
	FindMatches(ctx context.Context, chunk sources.Chunk) ([]string, error)
	Verify(ctx context.Context, token string) (Result, error)
}

type MatchFunc func(context.Context, sources.Chunk) ([]string, error)
type VerifyFunc func(context.Context, string) (Result, error)

type StandardDetector struct {
	dType       detectorspb.DetectorType
	description string

	keywords []string
	Pattern  *regexp.Regexp

	matchFunc  MatchFunc
	verifyFunc VerifyFunc
}

var (
	_ interface {
		SinglePartDetector
		Detector
	} = (*StandardDetector)(nil)
)

func (d *StandardDetector) Type() detectorspb.DetectorType {
	return d.dType
}

func (d *StandardDetector) Keywords() []string {
	return d.keywords
}

func (d *StandardDetector) Description() string {
	return d.description
}

func (d *StandardDetector) FromData(_ aCtx.Context, _ bool, _ []byte) ([]Result, error) {
	// No-op
	return nil, nil
}

func (d *StandardDetector) FindMatches(ctx context.Context, chunk sources.Chunk) ([]string, error) {
	return d.matchFunc(ctx, chunk)
}

func (d *StandardDetector) defaultMatchFunc(ctx context.Context, chunk sources.Chunk) ([]string, error) {
	dataStr := string(chunk.Data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range d.Pattern.FindAllStringSubmatch(dataStr, -1) {
		var m string
		if d.Pattern.NumSubexp() > 0 {
			// The first non-empty match.
			_, m = firstNonEmptyMatch(match, 1)
		} else {
			// The entire match.
			m = match[0]
		}
		uniqueMatches[m] = struct{}{}
	}
	ctx.Logger().Info("Found matches:", "matches", uniqueMatches)
	return maps.Keys(uniqueMatches), nil
}

func (d *StandardDetector) Verify(ctx context.Context, token string) (Result, error) {
	return d.verifyFunc(ctx, token)
}

func (d *StandardDetector) defaultVerifyFunc(ctx context.Context, token string) (Result, error) {
	ctx.Logger().Info("Verifying match", "token", token)
	return Result{
		Status:    Skipped,
		Reason:    "lol",
		ExtraData: nil,
	}, nil
}

// firstNonEmptyMatch returns the index and value of the first non-empty match.
// If no non-empty match is found, it will return: 0, "".
func firstNonEmptyMatch(matches []string, skip int) (int, string) {
	if len(matches) < skip {
		return 0, ""
	}
	// The first index is the entire matched string.
	for i, val := range matches[skip:] {
		if val != "" {
			return i + skip, val
		}
	}
	return 0, ""
}

// Builder
type DetectorBuilder interface {
	Type(detectorspb.DetectorType) DetectorBuilder
	Description(string) DetectorBuilder
	Keywords(...string) DetectorBuilder
	Pattern(*regexp.Regexp) DetectorBuilder
	MatchFunction(MatchFunc) DetectorBuilder
	VerifyFunction(VerifyFunc) DetectorBuilder

	Build() *StandardDetector
}

func NewDetectorBuilder() DetectorBuilder {
	return &detectorBuilder{
		d: &StandardDetector{},
	}
}

type detectorBuilder struct {
	d *StandardDetector

	t          *detectorspb.DetectorType
	matchFunc  *MatchFunc
	verifyFunc *VerifyFunc
}

func (db *detectorBuilder) Type(detectorType detectorspb.DetectorType) DetectorBuilder {
	db.t = &detectorType
	return db
}

func (db *detectorBuilder) Description(description string) DetectorBuilder {
	db.d.description = description
	return db
}

func (db *detectorBuilder) Keywords(keywords ...string) DetectorBuilder {
	db.d.keywords = keywords
	return db
}

func (db *detectorBuilder) Pattern(pattern *regexp.Regexp) DetectorBuilder {
	db.d.Pattern = pattern
	return db
}

func (db *detectorBuilder) MatchFunction(matchFunc MatchFunc) DetectorBuilder {
	db.d.matchFunc = matchFunc
	return db
}

func (db *detectorBuilder) VerifyFunction(verifyFunc VerifyFunc) DetectorBuilder {
	db.d.verifyFunc = verifyFunc
	return db
}

func (db *detectorBuilder) Build() *StandardDetector {
	if db.t == nil {
		log.Fatalf("no type")
	} else {
		db.d.dType = *db.t
	}
	if db.d.Description() == "" {
		log.Fatalf("no description")
	}
	if len(db.d.keywords) == 0 {
		log.Fatalf("no keywords")
	}
	if db.d.Pattern == nil {
		log.Fatalf("no pattern")
	}
	if db.matchFunc == nil {
		db.d.matchFunc = db.d.defaultMatchFunc
	}
	if db.verifyFunc == nil {
		db.d.verifyFunc = db.d.defaultVerifyFunc
	}

	return db.d
}

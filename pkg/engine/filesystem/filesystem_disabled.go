//go:build no_filesystem

package filesystem

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func Scan(_ context.Context, _ sources.FilesystemConfig, _ *engine.Engine) (sources.JobProgressRef, error) {
	return sources.JobProgressRef{}, engine.ErrSourceDisabled
}

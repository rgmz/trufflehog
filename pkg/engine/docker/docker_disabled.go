//go:build no_docker

package docker

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func Scan(_ context.Context, _ sources.DockerConfig, _ *engine.Engine) (sources.JobProgressRef, error) {
	return sources.JobProgressRef{}, engine.ErrSourceDisabled
}

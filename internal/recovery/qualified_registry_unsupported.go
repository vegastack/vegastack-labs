//go:build !linux

package recovery

import (
	"context"
	"time"
)

func LoadSystemQualifiedAdapters(context.Context, []BoundaryRequirement, time.Time) (QualifiedAdapters, error) {
	return QualifiedAdapters{}, ErrWitnessUnavailable
}

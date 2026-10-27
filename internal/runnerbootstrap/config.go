// Package runnerbootstrap consumes short-lived registration credentials through
// a private terminal. Configuration is not permission to execute a job.
package runnerbootstrap

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

type Config struct {
	Directory, Organization, Name, Group string
	Labels                               []string
	ExpiresAt                            time.Time
	Check                                func() error
}

// Receipt.Stage must survive errors; attempted registration can require cleanup.
type Receipt struct{ Stage string }

var (
	errInput       = failure.New(generated.ErrorCodeInputInvalid, "runner-bootstrap", false)
	errDenied      = failure.New(generated.ErrorCodeAuthorizationDenied, "runner-bootstrap", false)
	errIntegrity   = failure.New(generated.ErrorCodeIntegrityFailure, "runner-bootstrap", false)
	errUnavailable = failure.New(generated.ErrorCodeDependencyUnavailable, "runner-bootstrap", false)
	errInterrupted = failure.New(generated.ErrorCodeInterrupted, "runner-bootstrap", false)
	safeName       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	organization   = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$`)
)

func validConfig(c Config, v *credentialref.Value) bool {
	now := time.Now()
	if !organization.MatchString(c.Organization) || !safeName.MatchString(c.Name) || len(c.Group) == 0 || len(c.Group) > 128 || strings.TrimSpace(c.Group) != c.Group || len(c.Labels) == 0 || len(c.Labels) > 64 || c.Check == nil || !c.ExpiresAt.After(now) || c.ExpiresAt.After(now.Add(time.Hour)) {
		return false
	}
	for _, b := range []byte(c.Group) {
		if b < 32 || b > 126 {
			return false
		}
	}
	seen := map[string]bool{}
	for _, label := range c.Labels {
		key := strings.ToLower(label)
		if !safeName.MatchString(label) || seen[key] {
			return false
		}
		seen[key] = true
	}
	token := v.Bytes()
	if len(token) < 1 || len(token) > 4096 {
		return false
	}
	for _, b := range token {
		if b < 33 || b > 126 {
			return false
		}
	}
	return true
}
func current(ctx context.Context, c Config) error {
	if ctx.Err() != nil || !c.ExpiresAt.After(time.Now()) {
		return errInterrupted
	}
	if c.Check() == nil {
		if ctx.Err() == nil && c.ExpiresAt.After(time.Now()) {
			return nil
		}
		return errInterrupted
	}
	return errDenied
}

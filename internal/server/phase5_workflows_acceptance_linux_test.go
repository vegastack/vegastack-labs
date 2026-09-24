//go:build linux

package server_test

import (
	"net/http"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/api"
)

func TestPhase5BrowserCanReadSafeFactsAndCannotReachProtectedEffects(t *testing.T) {
	t.Parallel()

	for _, path := range []string{
		"/api/v1/backups/status",
		"/api/v1/recovery-points",
		"/api/v1/audit-checkpoints",
		"/api/v1/audit-history/verification",
		"/api/v1/restore-plans",
		"/api/v1/scheduled-job-policies",
		"/api/v1/scheduled-jobs",
	} {
		if !api.RemoteReadRequestAllowed(http.MethodGet, path) {
			t.Errorf("browser-safe Phase 5 read denied: %s", path)
		}
	}

	for _, path := range []string{
		"/api/v1/backup-policies/policy-a/jobs",
		"/api/v1/recovery-points/point-a/verifications",
		"/api/v1/restore-plans/restore-a/runs",
		"/api/v1/restore-plans/restore-a/verifications",
		"/api/v1/scheduled-job-policies/policy-a/occurrences",
		"/api/v1/audit-checkpoints",
	} {
		if api.RemoteReadRequestAllowed(http.MethodPost, path) {
			t.Errorf("browser reached protected Phase 5 effect: %s", path)
		}
	}

	for _, path := range []string{
		"/api/v1/gates/G-008/check",
		"/api/v1/gates/G-008/evidence",
		"/api/v1/recovery-points/point-a/restore-drafts",
	} {
		if !api.RemoteReadRequestAllowed(http.MethodPost, path) {
			t.Errorf("reviewed inert browser mutation denied: %s", path)
		}
	}
}

func TestPhase5ConstrainedSSHUsesGeneratedOperatorAllowlist(t *testing.T) {
	t.Parallel()

	for _, path := range []string{
		"/api/v1/backup-policies/policy-a/jobs",
		"/api/v1/recovery-points/point-a/verifications",
		"/api/v1/recovery-points/point-a/restore-plans",
		"/api/v1/restore-plans/restore-a/runs",
		"/api/v1/restore-plans/restore-a/verifications",
		"/api/v1/scheduled-job-policies/policy-a/occurrences",
	} {
		if !api.ConstrainedSSHRequestAllowed(http.MethodPost, path) {
			t.Errorf("generated operator route absent from constrained SSH: %s", path)
		}
	}

	for _, path := range []string{
		"/api/v1/credential-references/ref-a/import-stream",
		"/api/v1/database/exports/raw",
		"/api/v1/session",
	} {
		if api.ConstrainedSSHRequestAllowed(http.MethodPost, path) {
			t.Errorf("forbidden constrained SSH route admitted: %s", path)
		}
	}
}

//go:build linux

package cli

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type persistentLifecycleOperations struct {
	*stubCredentialOperations
	service api.CredentialLifecycleService
}

func (operations persistentLifecycleOperations) CreateCredentialLifecycleDraft(ctx context.Context, _ string, input generated.CredentialLifecycleRequest) (localapi.TypedResponse[generated.CredentialLifecycleSubmission], error) {
	_, err := operations.service.CreateDraft(ctx, input, identity.Principal{ID: "operator-lifecycle", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman})
	return localapi.TypedResponse[generated.CredentialLifecycleSubmission]{}, err
}

func TestLifecycleCLIDenialsPreserveRealStoreState(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "control.db")
	clock := func() time.Time { return time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC) }
	authority, err := store.Open(ctx, store.Config{DatabasePath: path, Mode: store.InitializeNew, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "test", BuildVersion: "test", Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = authority.Close() })
	references := store.NewCredentialRepository(authority)
	revisions := store.NewPlanRepository(authority)
	declarations, err := change.NewService(store.NewDeclarationRepository(authority), clock)
	if err != nil {
		t.Fatal(err)
	}
	service, err := api.NewCredentialLifecycleService(references, revisions, declarations, authorization.NewEvaluator(store.NewEffectiveAuthorizationRepository(authority)))
	if err != nil {
		t.Fatal(err)
	}
	operations := persistentLifecycleOperations{stubCredentialOperations: successfulCredentialOperations(t), service: service}
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, mode := range []string{"cross-action", "value", "ciphertextFingerprint", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			raw := syntheticLifecycleRequest(t, generated.CommandNameCredentialStage)
			command := "stage"
			if mode == "cross-action" {
				command = "revoke"
			} else {
				field := mode
				if mode == "unknown" {
					field = "privateUnknown"
				}
				raw = append(raw[:len(raw)-1], []byte(`,"`+field+`":"private-canary"}`)...)
			}
			var beforeBindings int
			if err := db.QueryRow(`SELECT COUNT(*) FROM credential_lifecycle_bindings`).Scan(&beforeBindings); err != nil {
				t.Fatal(err)
			}
			beforeRevision, err := revisions.CurrentRevision(ctx)
			if err != nil {
				t.Fatal(err)
			}
			code, stdout, stderr := runTestAppWithOptions(t, ctx, []string{"credential", command, "--config", "profile.json", "--file", "request.json", "--output", "json"}, nil, WithControlOperations(successfulControlOperations(t), &stubFileReader{content: raw}), WithCredentialControlOperations(operations))
			var afterBindings int
			if err := db.QueryRow(`SELECT COUNT(*) FROM credential_lifecycle_bindings`).Scan(&afterBindings); err != nil {
				t.Fatal(err)
			}
			afterRevision, err := revisions.CurrentRevision(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if code == 0 || beforeBindings != afterBindings || beforeRevision != afterRevision || strings.Contains(stdout+stderr, "private-canary") {
				t.Fatalf("CLI denial persisted or leaked: mode=%s code=%d bindings=%d→%d revision=%+v→%+v output=%s%s", mode, code, beforeBindings, afterBindings, beforeRevision, afterRevision, stdout, stderr)
			}
		})
	}
}

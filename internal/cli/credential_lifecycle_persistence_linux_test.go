//go:build linux

package cli

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type persistentLifecycleOperations struct {
	*stubCredentialOperations
	service api.CredentialLifecycleService
}

func (operations persistentLifecycleOperations) CreateCredentialLifecycleDraft(ctx context.Context, _ string, input generated.CredentialLifecycleRequest) (localapi.TypedResponse[generated.CredentialLifecycleSubmission], error) {
	var zero localapi.TypedResponse[generated.CredentialLifecycleSubmission]
	submission, err := operations.service.CreateDraft(ctx, input, identity.Principal{ID: "operator-lifecycle", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman})
	if err != nil {
		return zero, err
	}
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}, func() (string, error) { return "request-lifecycle-cli", nil })
	envelope, err := factory.Success("api.v1.credential-lifecycle-drafts.create", submission.RecoveryEpoch, submission.StateRevision, submission)
	if err != nil {
		return zero, err
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		return zero, err
	}
	return localapi.TypedResponse[generated.CredentialLifecycleSubmission]{Raw: append(raw, '\n'), Result: envelope, Data: submission}, nil
}

func lifecycleCLIDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func TestLifecycleCLIValidDraftThenDenialsPreserveRealStoreState(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "control.db")
	clock := func() time.Time { return time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC) }
	authority, err := store.Open(ctx, store.Config{DatabasePath: path, Mode: store.InitializeNew, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "test", BuildVersion: "test", Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = authority.Close() })
	references := store.NewCredentialRepository(authority)
	revisions := store.NewPlanRepository(authority)
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, `INSERT INTO effective_authorization_principals(principal_id,principal_kind,status,grant_revision,created_at,updated_at) VALUES('operator-lifecycle','human','active',1,'2026-09-21T12:00:00Z','2026-09-21T12:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO effective_authorization_grants(grant_id,principal_id,role_id,action,capability,resource_kind,resource_id,branch,grant_revision,status,created_at,updated_at) VALUES('grant-lifecycle-author','operator-lifecycle','author','author','credential.lifecycle.author','credential-reference','reference-lifecycle',NULL,1,'active','2026-09-21T12:00:00Z','2026-09-21T12:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	current, err := revisions.CurrentRevision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	importInput := generated.CredentialImportRequest{Schema: generated.SchemaIDCredentialImportRequest, SchemaVersion: "1.1.0", ReferenceID: "reference-lifecycle", ConsumerID: "consumer-lifecycle", PurposeID: "purpose-lifecycle", TargetID: "target-lifecycle", ResolverID: "native-systemd", MaterialVersion: "version-1", ExpectedStateRevision: current.StateRevision, RecoveryEpoch: current.RecoveryEpoch, IdempotencyKey: "import-version-1"}
	importInput.TargetDigest = credentialref.ImportTargetDigest(importInput)
	imported, err := references.PutImportDraft(ctx, store.CredentialImportDraftRequest{Input: importInput, DraftID: "draft-version-1", CiphertextName: "ciphertext-version-1", CiphertextFingerprint: lifecycleCLIDigest("ciphertext-version-1"), Expected: current, Attribution: audit.Attribution{AuthenticatedPrincipalID: "operator-lifecycle", AuthenticatedPrincipalMethod: identity.LocalOSPeerMethod}, KeyDigest: lifecycleCLIDigest("import-key"), RequestDigest: lifecycleCLIDigest("import-request")})
	if err != nil {
		t.Fatal(err)
	}
	declarations, err := change.NewService(store.NewDeclarationRepository(authority), clock)
	if err != nil {
		t.Fatal(err)
	}
	service, err := api.NewCredentialLifecycleService(references, revisions, declarations, authorization.NewEvaluator(store.NewEffectiveAuthorizationRepository(authority)))
	if err != nil {
		t.Fatal(err)
	}
	operations := persistentLifecycleOperations{stubCredentialOperations: successfulCredentialOperations(t), service: service}
	current, err = revisions.CurrentRevision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	request := generated.CredentialLifecycleRequest{Schema: generated.SchemaIDCredentialLifecycleRequest, SchemaVersion: "1.2.0", Action: "credential.stage", DraftID: &imported.DraftID, ReferenceID: imported.ReferenceID, ConsumerIDs: []string{"consumer-lifecycle"}, RequiredDeniedConsumerIDs: []string{}, MaterialVersion: "version-1", ResolverID: "native-systemd", TargetID: "target-lifecycle", ExpectedStateRevision: current.StateRevision, RecoveryEpoch: current.RecoveryEpoch, IdempotencyKey: "stage-draft-version-1"}
	request.TargetDigest = credentialref.LifecycleTargetDigest(request)
	validRaw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runTestAppWithOptions(t, ctx, []string{"credential", "stage", "--config", "profile.json", "--file", "request.json", "--output", "json"}, nil, WithControlOperations(successfulControlOperations(t), &stubFileReader{content: validRaw}), WithCredentialControlOperations(operations))
	var envelope generated.RunResult
	var submission generated.CredentialLifecycleSubmission
	if err := json.Unmarshal([]byte(stdout), &envelope); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(envelope.Data, &submission); err != nil {
		t.Fatal(err)
	}
	var persisted int
	if err := db.QueryRow(`SELECT COUNT(*) FROM credential_lifecycle_bindings`).Scan(&persisted); err != nil {
		t.Fatal(err)
	}
	if code != 0 || stderr != "" || persisted != 1 || submission.Status != "draft" || submission.Action != "credential.stage" || submission.ReferenceID != request.ReferenceID || submission.ChangeID == "" || submission.StateRevision != request.ExpectedStateRevision+2 || strings.Contains(stdout, "ciphertext") {
		t.Fatalf("valid CLI did not create metadata-only durable draft: code=%d bindings=%d result=%+v stderr=%q", code, persisted, submission, stderr)
	}
	stored, err := references.LookupLifecycleDraft(ctx, submission.ChangeID, 1, submission.OperationID)
	if err != nil || stored.ReferenceID != request.ReferenceID || stored.ImportDraftStateRevision == nil || *stored.ImportDraftStateRevision != imported.StateRevision {
		t.Fatalf("valid CLI draft lacked sealed origin: binding=%+v err=%v", stored, err)
	}
	humanCode, humanOutput, humanError := runTestAppWithOptions(t, ctx, []string{"credential", "stage", "--config", "profile.json", "--file", "request.json", "--output", "human"}, nil, WithControlOperations(successfulControlOperations(t), &stubFileReader{content: validRaw}), WithCredentialControlOperations(operations))
	wantHuman := "Credential lifecycle draft draft\nAction: credential.stage\nReference: reference-lifecycle\nChange: " + submission.ChangeID + "\nState revision: " + fmt.Sprint(submission.StateRevision) + "\nRecovery epoch: " + fmt.Sprint(submission.RecoveryEpoch) + "\n"
	if humanCode != 0 || humanError != "" || humanOutput != wantHuman {
		t.Fatalf("real CLI replay rendered wrong human output: code=%d output=%q stderr=%q", humanCode, humanOutput, humanError)
	}
	current, err = revisions.CurrentRevision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	request.ExpectedStateRevision = current.StateRevision
	request.IdempotencyKey = "stage-draft-version-1-next"
	request.TargetDigest = credentialref.LifecycleTargetDigest(request)
	validRaw, err = json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"cross-action", "value", "ciphertextFingerprint", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			raw := append([]byte(nil), validRaw...)
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
	// The exact unmodified control request must still pass at the same revision;
	// otherwise the preceding denied-row comparisons would be vacuous.
	code, stdout, stderr = runTestAppWithOptions(t, ctx, []string{"credential", "stage", "--config", "profile.json", "--file", "request.json", "--output", "json"}, nil, WithControlOperations(successfulControlOperations(t), &stubFileReader{content: validRaw}), WithCredentialControlOperations(operations))
	if err := db.QueryRow(`SELECT COUNT(*) FROM credential_lifecycle_bindings`).Scan(&persisted); err != nil {
		t.Fatal(err)
	}
	finalRevision, err := revisions.CurrentRevision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 || stderr != "" || persisted != 2 || finalRevision.StateRevision != request.ExpectedStateRevision+2 || strings.Contains(stdout, "ciphertext") {
		t.Fatalf("second valid CLI control did not persist: code=%d bindings=%d revision=%+v stderr=%q", code, persisted, finalRevision, stderr)
	}
}

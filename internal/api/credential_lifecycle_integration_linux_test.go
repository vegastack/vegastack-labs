//go:build linux

package api

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func lifecyclePublicDigest(text string) string {
	sum := sha256.Sum256([]byte(text))
	return "sha256:" + hex.EncodeToString(sum[:])
}

type lifecyclePublicFixture struct {
	authority  *store.Store
	references *store.CredentialRepository
	revisions  *store.PlanRepository
	service    CredentialLifecycleService
	principal  identity.Principal
	clock      func() time.Time
	path       string
}

func newLifecyclePublicFixture(t *testing.T) *lifecyclePublicFixture {
	t.Helper()
	ctx := context.Background()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "control.db")
	clock := func() time.Time { return time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC) }
	authority, err := store.Open(ctx, store.Config{DatabasePath: path, Mode: store.InitializeNew, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "lifecycle-test", BuildVersion: "lifecycle-test", Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = authority.Close() })
	// Test-only initial policy fixture; runtime decisions use the real persisted
	// effective-policy repository/evaluator. No production client writes SQLite.
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, principal := range []string{"operator-lifecycle", "human-lifecycle"} {
		if _, err := db.ExecContext(ctx, `INSERT INTO effective_authorization_principals(principal_id,principal_kind,status,grant_revision,created_at,updated_at) VALUES(?,'human','active',1,'2026-09-18T12:00:00Z','2026-09-18T12:00:00Z')`, principal); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO effective_authorization_principals(principal_id,principal_kind,status,grant_revision,created_at,updated_at) VALUES('agent-lifecycle','agent','active',1,'2026-09-18T12:00:00Z','2026-09-18T12:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO effective_authorization_grants(grant_id,principal_id,role_id,action,capability,resource_kind,resource_id,branch,grant_revision,status,created_at,updated_at) VALUES('grant-lifecycle-author','operator-lifecycle','author','author','credential.lifecycle.author','credential-reference','reference-lifecycle',NULL,1,'active','2026-09-18T12:00:00Z','2026-09-18T12:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	for _, grant := range []struct{ action, capability, kind string }{{"acknowledge", "plan.acknowledge", "plan-target"}, {"execute", "credential.stage", "execution-target"}, {"execute", "credential.activate", "execution-target"}, {"execute", "credential.rotate", "execution-target"}, {"execute", "credential.revoke", "execution-target"}, {"execute", "credential.recover", "execution-target"}} {
		if _, err := db.ExecContext(ctx, `INSERT INTO effective_authorization_grants(grant_id,principal_id,role_id,action,capability,resource_kind,resource_id,branch,grant_revision,status,created_at,updated_at) VALUES(?,'human-lifecycle','control-plane-admin',?,?,?,'target-lifecycle','human',1,'active','2026-09-18T12:00:00Z','2026-09-18T12:00:00Z')`, "grant-lifecycle-"+grant.action+"-"+grant.capability, grant.action, grant.capability, grant.kind); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO effective_authorization_grants(grant_id,principal_id,role_id,action,capability,resource_kind,resource_id,branch,grant_revision,status,created_at,updated_at) VALUES('grant-lifecycle-agent-stage','agent-lifecycle','control-plane-admin','execute','credential.stage','execution-target','target-lifecycle','human',1,'active','2026-09-18T12:00:00Z','2026-09-18T12:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	refs := store.NewCredentialRepository(authority)
	revisions := store.NewPlanRepository(authority)
	declarations, err := change.NewService(store.NewDeclarationRepository(authority), clock)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewCredentialLifecycleService(refs, revisions, declarations, authorization.NewEvaluator(store.NewEffectiveAuthorizationRepository(authority)))
	if err != nil {
		t.Fatal(err)
	}
	return &lifecyclePublicFixture{authority: authority, references: refs, revisions: revisions, service: service, principal: identity.Principal{ID: "operator-lifecycle", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}, clock: clock, path: path}
}

func (fixture *lifecyclePublicFixture) importDraft(t *testing.T, version string) generated.CredentialImportSubmission {
	t.Helper()
	ctx := context.Background()
	current, err := fixture.revisions.CurrentRevision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	input := generated.CredentialImportRequest{Schema: generated.SchemaIDCredentialImportRequest, SchemaVersion: "1.1.0", ReferenceID: "reference-lifecycle", ConsumerID: "consumer-lifecycle", PurposeID: "purpose-lifecycle", TargetID: "target-lifecycle", ResolverID: "native-systemd", MaterialVersion: version, ExpectedStateRevision: current.StateRevision, RecoveryEpoch: current.RecoveryEpoch, IdempotencyKey: "import-" + version}
	input.TargetDigest = credentialref.ImportTargetDigest(input)
	imported, err := fixture.references.PutImportDraft(ctx, store.CredentialImportDraftRequest{Input: input, DraftID: "draft-" + version, CiphertextName: "ciphertext-" + version, CiphertextFingerprint: lifecyclePublicDigest("ciphertext-" + version), Expected: current, Attribution: audit.Attribution{AuthenticatedPrincipalID: fixture.principal.ID, AuthenticatedPrincipalMethod: fixture.principal.Method}, KeyDigest: lifecyclePublicDigest("import-key-" + version), RequestDigest: lifecyclePublicDigest("import-request-" + version)})
	if err != nil {
		t.Fatal(err)
	}
	return imported
}

func (fixture *lifecyclePublicFixture) stageRequest(t *testing.T, imported generated.CredentialImportSubmission) generated.CredentialLifecycleRequest {
	t.Helper()
	current, err := fixture.revisions.CurrentRevision(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	input := generated.CredentialLifecycleRequest{Schema: generated.SchemaIDCredentialLifecycleRequest, SchemaVersion: "1.2.0", Action: "credential.stage", DraftID: &imported.DraftID, ReferenceID: imported.ReferenceID, ConsumerIDs: []string{"consumer-lifecycle"}, RequiredDeniedConsumerIDs: []string{}, MaterialVersion: imported.DraftID[len("draft-"):], ResolverID: "native-systemd", TargetID: "target-lifecycle", ExpectedStateRevision: current.StateRevision, RecoveryEpoch: current.RecoveryEpoch, IdempotencyKey: "stage-" + imported.DraftID}
	input.TargetDigest = credentialref.LifecycleTargetDigest(input)
	return input
}

func TestCredentialLifecyclePublicDraftIsInertAndOriginSealed(t *testing.T) {
	fixture := newLifecyclePublicFixture(t)
	imported := fixture.importDraft(t, "version-1")
	request := fixture.stageRequest(t, imported)
	submission, err := fixture.service.CreateDraft(context.Background(), request, fixture.principal)
	if err != nil {
		t.Fatal(err)
	}
	if submission.Status != "draft" || submission.ChangeID == "" || submission.StateRevision != request.ExpectedStateRevision+2 {
		t.Fatalf("inert submission: %+v", submission)
	}
	if _, err := fixture.references.GetReference(context.Background(), request.ReferenceID); store.Code(err) != generated.ErrorCodeResourceNotFound {
		t.Fatalf("draft must not append any applied version: %v", err)
	}
	draft, err := store.NewDeclarationRepository(fixture.authority).GetRevision(context.Background(), submission.ChangeID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if draft.Status != "draft" || len(draft.Operations) != 1 || draft.Operations[0].AdapterID != "core.credential" || draft.Operations[0].ArtifactDigest != imported.CiphertextFingerprint {
		t.Fatalf("draft not sealed to server-derived fingerprint: %+v", draft)
	}
	binding, err := fixture.references.LookupLifecycleDraft(context.Background(), submission.ChangeID, 1, submission.OperationID)
	if err != nil || binding.ImportDraftStateRevision == nil || *binding.ImportDraftStateRevision != imported.StateRevision || binding.ImportDraftConsumerID == nil || *binding.ImportDraftConsumerID != "consumer-lifecycle" || binding.ImportDraftPurposeID == nil || *binding.ImportDraftPurposeID != "purpose-lifecycle" || binding.StateRevision != request.ExpectedStateRevision+3 {
		t.Fatalf("origin and future execution identity: %+v err=%v", binding, err)
	}
	before, err := fixture.revisions.CurrentRevision(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := fixture.service.CreateDraft(context.Background(), request, fixture.principal)
	if err != nil || replayed != submission {
		t.Fatalf("exact replay: %+v err=%v", replayed, err)
	}
	after, err := fixture.revisions.CurrentRevision(context.Background())
	if err != nil || before != after {
		t.Fatalf("replay wrote state: before=%+v after=%+v err=%v", before, after, err)
	}
	substituted := request
	substituted.TargetID = "target-other"
	substituted.TargetDigest = credentialref.LifecycleTargetDigest(substituted)
	if _, err := fixture.service.CreateDraft(context.Background(), substituted, fixture.principal); err == nil {
		t.Fatal("same key allowed substituted request")
	}
}

func TestCredentialLifecyclePublicDraftRejectsUnsafeMetadataWithoutMutation(t *testing.T) {
	for _, mode := range []string{"browser", "wrong-scope", "stale-revision", "wrong-epoch", "wrong-target-digest", "wrong-draft", "wrong-version", "wrong-consumer", "wrong-resolver", "wrong-target"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newLifecyclePublicFixture(t)
			imported := fixture.importDraft(t, "version-1")
			input := fixture.stageRequest(t, imported)
			principal := fixture.principal
			switch mode {
			case "browser":
				principal.Method = identity.CloudflareAccessMethod
			case "wrong-scope":
				principal.ID = "human-lifecycle"
			case "stale-revision":
				input.ExpectedStateRevision--
			case "wrong-epoch":
				input.RecoveryEpoch++
			case "wrong-draft":
				value := "draft-other"
				input.DraftID = &value
			case "wrong-version":
				input.MaterialVersion = "version-other"
			case "wrong-consumer":
				input.ConsumerIDs = []string{"consumer-other"}
			case "wrong-resolver":
				input.ResolverID = "resolver-other"
			case "wrong-target":
				input.TargetID = "target-other"
			}
			input.TargetDigest = credentialref.LifecycleTargetDigest(input)
			if mode == "wrong-target-digest" {
				input.TargetDigest = lifecyclePublicDigest("substitution")
			}
			before, err := fixture.revisions.CurrentRevision(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fixture.service.CreateDraft(context.Background(), input, principal); err == nil {
				t.Fatal("unsafe metadata was accepted")
			}
			after, err := fixture.revisions.CurrentRevision(context.Background())
			if err != nil || before != after {
				t.Fatalf("denied draft mutated state: before=%+v after=%+v err=%v", before, after, err)
			}
		})
	}
}

func TestLifecycleRotateAndRecoverDraftsRejectOriginSubstitution(t *testing.T) {
	for _, action := range []string{"credential.rotate", "credential.recover"} {
		for _, mode := range []string{"wrong-draft", "wrong-version", "wrong-consumer", "wrong-target", "wrong-resolver"} {
			t.Run(action+"/"+mode, func(t *testing.T) {
				fixture := newLifecyclePublicFixture(t)
				if action == "credential.recover" {
					// Test-only restored-epoch setup, never a runtime recovery authority.
					db, err := sql.Open("sqlite3", fixture.path)
					if err != nil {
						t.Fatal(err)
					}
					_, err = db.Exec("UPDATE system_meta SET recovery_epoch=1 WHERE id=1")
					_ = db.Close()
					if err != nil {
						t.Fatal(err)
					}
				}
				imported := fixture.importDraft(t, "version-2")
				input := fixture.stageRequest(t, imported)
				input.Action = action
				if action == "credential.rotate" {
					prior := "version-1"
					input.PriorMaterialVersion = &prior
					input.RequiredDeniedConsumerIDs = []string{"consumer-denied"}
				}
				if action == "credential.recover" {
					priorEpoch := int64(0)
					digest := lifecyclePublicDigest("synthetic-custody")
					input.PriorRecoveryEpoch = &priorEpoch
					input.CustodyProofDigest = &digest
					input.FormerControllerFenceDigest = &digest
				}
				switch mode {
				case "wrong-draft":
					draft := "missing-draft"
					input.DraftID = &draft
				case "wrong-version":
					input.MaterialVersion = "version-other"
				case "wrong-consumer":
					input.ConsumerIDs = []string{"consumer-other"}
				case "wrong-target":
					input.TargetID = "target-other"
				case "wrong-resolver":
					input.ResolverID = "resolver-other"
				}
				input.TargetDigest = credentialref.LifecycleTargetDigest(input)
				before, err := fixture.revisions.CurrentRevision(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if _, err := fixture.service.CreateDraft(context.Background(), input, fixture.principal); err == nil {
					t.Fatal("substituted draft origin accepted")
				}
				after, err := fixture.revisions.CurrentRevision(context.Background())
				if err != nil || before != after {
					t.Fatalf("origin denial wrote state: %+v %+v %v", before, after, err)
				}
			})
		}
	}
}

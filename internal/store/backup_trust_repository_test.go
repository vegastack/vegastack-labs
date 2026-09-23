package store

import (
	"context"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

func backupTrustDraftFixture() generated.BackupTrustSourceDraftRequest {
	return generated.BackupTrustSourceDraftRequest{
		Schema: generated.SchemaIDBackupTrustSourceDraftRequest, SchemaVersion: "1.0.0",
		SourceID: "source-config-a", DependencyID: "config-a", DependencyKind: "config",
		ArtifactID: "artifact-config-a", ArtifactDigest: "sha256:" + strings.Repeat("a", 64),
		BundleDigest: "sha256:" + strings.Repeat("b", 64), TrustedRootReferenceID: "root-a",
		TrustRootDigest: "sha256:" + strings.Repeat("c", 64),
		SignerIdentity:  "https://example.invalid/vegastack/synthetic-release",
		SignerIssuer:    "https://issuer.example.invalid", Revision: 1, RecoveryEpoch: 0,
		ExpectedStateRevision: 0, IdempotencyKey: "trust-source-a",
	}
}

func TestBackupTrustDraftCannotActivateItself(t *testing.T) {
	repository := NewBackupRepository(openTestStore(t))
	attribution := audit.Attribution{AuthenticatedPrincipalID: "human-a", AuthenticatedPrincipalMethod: "local-os-peer"}
	draft, err := repository.CreateBackupTrustSourceDraft(context.Background(), backupTrustDraftFixture(), attribution)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.GetCurrentBackupTrustSource(context.Background(), draft.SourceID, draft.Revision, draft.StateRevision, draft.RecoveryEpoch); err == nil {
		t.Fatal("inert trust draft became current")
	}
	var got int
	if err := repository.store.conn.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM backup_trust_source_bindings`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != 0 {
		t.Fatalf("draft created %d current bindings", got)
	}
}

func TestBackupTrustSourceRequiresExactBindingAndRevocationWins(t *testing.T) {
	ctx := context.Background()
	repository := NewBackupRepository(openTestStore(t))
	attribution := audit.Attribution{AuthenticatedPrincipalID: "human-a", AuthenticatedPrincipalMethod: "local-os-peer"}
	draft, err := repository.CreateBackupTrustSourceDraft(ctx, backupTrustDraftFixture(), attribution)
	if err != nil {
		t.Fatal(err)
	}
	apply := BackupTrustSourceApplyRequest{
		BindingID: "binding-a", SourceID: draft.SourceID, SourceRevision: draft.Revision, Status: "current",
		PlanID: "plan-a", PlanDigest: "sha256:" + strings.Repeat("d", 64), RunID: "run-a", StepID: "step-a",
		LeaseID: "lease-a", DeclarationID: "declaration-a", DeclarationRevision: 1,
		Expected: RevisionToken{StateRevision: draft.StateRevision, RecoveryEpoch: draft.RecoveryEpoch}, Attribution: attribution,
	}
	current, err := repository.ApplyBackupTrustSource(ctx, apply)
	if err != nil || current.DependencyID != "config-a" || current.ArtifactDigest != backupTrustDraftFixture().ArtifactDigest {
		t.Fatalf("apply current = %#v, %v", current, err)
	}
	if _, err := repository.GetCurrentBackupTrustSourceForDependency(ctx, "config-a", "config", draft.StateRevision+1, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.GetCurrentBackupTrustSourceForDependency(ctx, "config-a", "config", draft.StateRevision, 0); err == nil {
		t.Fatal("stale state resolved current source")
	}
	apply.BindingID, apply.Status, apply.Expected.StateRevision = "binding-revoke-a", "revoked", draft.StateRevision+1
	if _, err := repository.ApplyBackupTrustSource(ctx, apply); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.GetCurrentBackupTrustSourceForDependency(ctx, "config-a", "config", draft.StateRevision+2, 0); err == nil {
		t.Fatal("revoked source remained current")
	}
}

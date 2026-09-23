package change

import (
	"context"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestRestoreChangeIsOneInertSealedCutover(t *testing.T) {
	request, source, fences, decision := validRestoreDraftInput()
	document, err := BuildRestoreChange(context.Background(), request, source, fences, decision)
	if err != nil {
		t.Fatal(err)
	}
	if document.DeclarationType != "recovery.restore" || document.Status != "draft" || len(document.Operations) != 1 || document.Operations[0].OperationType != "recovery.restore.cutover" || document.Operations[0].AdapterID != "core.recovery" || document.Operations[0].Idempotent || len(document.Extensions) != 1 || document.Extensions[0].Name != "x-restore-binding" || document.Operations[0].InputDigest != document.Extensions[0].ValueDigest {
		t.Fatalf("restore declaration = %#v", document)
	}
	request.NextRecoveryEpoch++
	if _, err := BuildRestoreChange(context.Background(), request, source, fences, decision); err == nil {
		t.Fatal("non-adjacent epoch accepted")
	}
}

func validRestoreDraftInput() (generated.RestoreRequest, generated.RestoreSourceBinding, []generated.RestoreFenceItem, generated.RestoreAuditDecision) {
	digest := "sha256:" + strings.Repeat("a", 64)
	source := generated.RestoreSourceBinding{Schema: generated.SchemaIDRestoreSourceBinding, SchemaVersion: "1.1.0", PointID: "point-a", PointDigest: digest, ManifestDigest: digest, VerificationDigest: digest, SourceClass: "local", RepositoryGenerationID: "generation-a", KeyReferenceID: "key-a", DeclaredRPOSeconds: 3600, CreatedAt: "2026-09-24T05:00:00Z", VerifiedAt: "2026-09-24T05:30:00Z", RecoveryEpoch: 2, DependencyDigests: []string{digest}}
	fences := []generated.RestoreFenceItem{{Schema: generated.SchemaIDRestoreFenceItem, SchemaVersion: "1.1.0", Boundary: "host-service", SubjectID: "former-host", TargetID: "control-a", AdapterID: "adapter-a", FormerIdentityID: "former-identity", RequiredEvidenceKinds: []string{"service-denied"}, Required: true, EvidenceIDs: []string{digest, "sha256:" + strings.Repeat("b", 64)}, EvidenceDigest: digest, Status: "required"}}
	decision := generated.RestoreAuditDecision{Schema: generated.SchemaIDRestoreAuditDecision, SchemaVersion: "1.1.0", LocalLastEventID: 4, IndependentLastEventID: 4, IndependentCheckpointDigest: digest, Strategy: "matched", DecisionDigest: digest}
	request := generated.RestoreRequest{Schema: generated.SchemaIDRestoreRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: 8, RecoveryEpoch: 2, TargetDigest: digest, IdempotencyKey: "restore-a", Source: source, Fences: fences, AuditDecision: decision, PointID: source.PointID, DependencyIDs: []string{"dependency-a"}, TargetIDs: []string{"control-a"}, PriorInstanceID: "instance-old", NewInstanceID: "instance-new", PriorRecoveryEpoch: 2, NextRecoveryEpoch: 3, FenceSetDigest: digest, AuditDecisionDigest: digest, CandidateDigest: digest,
		FormerHostID: "former-host", ReplacementHostID: "replacement-host", RecoveryDraftID: "draft-a", CiphertextFingerprint: digest, SourceAdmissionDigest: digest, FenceQualificationDigest: digest, RecoveryRunID: "run-a", RecoveryStepID: "step-a", RecoveryLeaseID: "lease-a", RecoveryChallengeID: "challenge-a", RecoveryReceiptID: "receipt-a"}
	return request, source, fences, decision
}

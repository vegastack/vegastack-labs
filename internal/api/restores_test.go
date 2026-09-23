package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/recovery"
	"github.com/vegastack/vegastack-labs/internal/result"
)

type restoreOperationsStub struct{ plan, run, verify int }

func (stub *restoreOperationsStub) Plan(context.Context, generated.RestoreRequest, identity.Principal) (generated.RestoreBinding, error) {
	stub.plan++
	return generated.RestoreBinding{}, nil
}
func (stub *restoreOperationsStub) Run(context.Context, generated.RestoreRunRequest, identity.Principal) (generated.RestoreBinding, error) {
	stub.run++
	return generated.RestoreBinding{}, nil
}
func (stub *restoreOperationsStub) Verify(context.Context, generated.RestoreVerifyRequest, identity.Principal) (generated.RestoreVerification, error) {
	stub.verify++
	return generated.RestoreVerification{}, nil
}
func (*restoreOperationsStub) Get(context.Context, string) (generated.BrowserRestoreStatus, error) {
	return generated.BrowserRestoreStatus{}, nil
}
func (*restoreOperationsStub) AuthorizationPlan(context.Context, string) (generated.Plan, error) {
	digest := "sha256:" + strings.Repeat("a", 64)
	return generated.Plan{Schema: generated.SchemaIDPlan, SchemaVersion: "1.0.0", PlanID: "plan-a", PlanDigest: digest, DeclarationID: "restore-a", Binding: generated.PlanBinding{RecoveryEpoch: 2, PriorStateRevision: 9, StateRevision: 10, DeclarationRevision: 2, ObservationFingerprint: digest, TargetDigest: digest, ReasonDigest: digest, PolicyVersion: "1.0.0", ToolVersion: "test", ContractVersion: "1.0.0"}, Operations: []generated.PlanOperation{{Sequence: 1, OperationID: "restore-cutover", OperationType: "recovery.restore.cutover", AdapterID: "core.recovery", ExecutorID: "executor-central", TargetID: "control-a", InputDigest: digest, ArtifactDigest: digest, Idempotent: false}, {Sequence: 2, OperationID: "canary-step-a", OperationType: "recovery.canary.noop", AdapterID: "core.recovery", ExecutorID: "executor-central", TargetID: "instance-new", InputDigest: digest, ArtifactDigest: digest, Idempotent: true}}, Status: "planned", Risk: "control-plane", AuthorizationBranch: "human", ExecutorMode: "central", CreatedAt: "2026-09-24T05:00:00Z", ExpiresAt: "2026-09-24T05:30:00Z", ReadableDigest: digest, Extensions: []generated.ContractExtension{{Name: "x-restore-binding", ValueDigest: digest}}}, nil
}

func TestRestorePostRoutesDenyExactTargetBeforeServiceMutation(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	secondDigest := "sha256:" + strings.Repeat("b", 64)
	source := generated.RestoreSourceBinding{Schema: generated.SchemaIDRestoreSourceBinding, SchemaVersion: "1.1.0", PointID: "point-a", PointDigest: digest, ManifestDigest: digest, VerificationDigest: digest, SourceClass: "local", RepositoryGenerationID: "generation-a", KeyReferenceID: "key-a", DeclaredRPOSeconds: 3600, CreatedAt: "2026-09-24T05:00:00Z", VerifiedAt: "2026-09-24T05:30:00Z", RecoveryEpoch: 2, DependencyDigests: []string{digest}, RequiredDependencies: []generated.RestoreDependencyBinding{{DependencyID: "binary-a", Kind: "binary", Digest: digest}}, TargetReleaseBuildID: "build-a", TargetToolVersion: "1.0.0", TargetSchemaVersion: "21"}
	fences, err := recovery.RequiredFenceSet([]recovery.FenceRequirement{{Boundary: "host-service", SubjectID: "former-host", FormerInstanceID: "instance-old", ReplacementInstanceID: "instance-new", TargetID: "control-a", AdapterID: "adapter-a", FormerIdentityID: "former-identity", ProfileID: "labs", ProfileVersion: "1.0.0", PolicyID: "policy-a", PolicyVersion: "1.0.0", ReleaseBuildID: "build-a", EvaluatorVersion: "1.0.0", RecoveryEpoch: 2, RequiredEvidenceKinds: []string{"alternate-process-denied", "service-denied"}}}, digest, secondDigest)
	if err != nil {
		t.Fatal(err)
	}
	plan := generated.RestoreRequest{Schema: generated.SchemaIDRestoreRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: 8, RecoveryEpoch: 2, TargetDigest: digest, IdempotencyKey: "restore-a", Source: source, Fences: fences.Items, AuditDecision: generated.RestoreAuditDecision{Schema: generated.SchemaIDRestoreAuditDecision, SchemaVersion: "1.1.0", LocalLastEventID: 4, IndependentLastEventID: 4, IndependentCheckpointDigest: digest, Strategy: "matched", DecisionDigest: digest}, PointID: "point-a", DependencyIDs: []string{"dependency-a"}, TargetIDs: []string{"control-a"}, PriorInstanceID: "instance-old", NewInstanceID: "instance-new", PriorRecoveryEpoch: 2, NextRecoveryEpoch: 3, FenceSetDigest: fences.FenceSetDigest, AuditDecisionDigest: digest, CandidateDigest: digest, FormerHostID: "former-host", ReplacementHostID: "replacement-host", RecoveryDraftID: "draft-a", CiphertextFingerprint: digest, SourceAdmissionDigest: digest, FenceQualificationDigest: secondDigest, RecoveryRunID: "run-a", RecoveryStepID: "step-a", RecoveryLeaseID: "lease-a", RecoveryChallengeID: "challenge-a", RecoveryReceiptID: "receipt-a", CanaryRunID: "canary-run-a", CanaryStepID: "canary-step-a", CanaryLeaseID: "canary-lease-a", CanaryChallengeID: "canary-challenge-a", CanaryReceiptID: "canary-receipt-a", CanaryBindingDigest: digest}
	run := generated.RestoreRunRequest{Schema: generated.SchemaIDRestoreRunRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: 10, RecoveryEpoch: 2, TargetDigest: digest, IdempotencyKey: "restore-run-a", Source: source, PointID: "point-a", PlanID: "plan-a", PlanDigest: digest, HumanAcknowledgementID: "ack-a", FenceSetDigest: digest, AuditDecisionDigest: digest, CandidateDigest: digest, PriorInstanceID: "instance-old", NewInstanceID: "instance-new", PriorRecoveryEpoch: 2, NextRecoveryEpoch: 3, RecoveryRunID: "run-a", RecoveryStepID: "step-a", RecoveryLeaseID: "lease-a", RecoveryChallengeID: "challenge-a", RecoveryReceiptID: "receipt-a", CanaryRunID: "canary-run-a", CanaryStepID: "canary-step-a", CanaryLeaseID: "canary-lease-a", CanaryChallengeID: "canary-challenge-a", CanaryReceiptID: "canary-receipt-a", CanaryBindingDigest: digest}
	verify := generated.RestoreVerifyRequest{Schema: generated.SchemaIDRestoreVerifyRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: 11, RecoveryEpoch: 3, TargetDigest: digest, IdempotencyKey: "restore-verify-a", Source: source, PointID: "point-a", PlanID: "plan-a", PlanDigest: digest, PriorInstanceID: "instance-old", NewInstanceID: "instance-new", PriorRecoveryEpoch: 2, NextRecoveryEpoch: 3, FenceSetDigest: digest, AuditDecisionDigest: digest, CandidateDigest: digest}
	for _, test := range []struct {
		name, path, capability, kind, target string
		body                                 any
	}{
		{"plan", "/api/v1/restores/plans", "recovery.restore.author", "recovery-point", "point-a", plan},
		{"run", "/api/v1/restores/plans/plan-a/run", "recovery.restore.cutover", "execution-target", "control-a", run},
		{"verify", "/api/v1/restores/plans/plan-a/verify", "recovery.restore.cutover", "execution-target", "control-a", verify},
	} {
		t.Run(test.name, func(t *testing.T) {
			operations := &restoreOperationsStub{}
			effective := &effectiveAuthorizationStub{decision: authorization.Decision{ReasonCode: authorization.ReasonGrantMissing}}
			app := newRestoreTestApplication(t, operations, effective)
			raw, err := json.Marshal(test.body)
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, test.path, bytes.NewReader(raw))
			request.Header.Set("Content-Type", "application/json")
			request = request.WithContext(identity.WithVerifiedPrincipal(request.Context(), identity.Principal{ID: "principal.test", Method: identity.LocalOSPeerMethod}))
			response := httptest.NewRecorder()
			app.ServeHTTP(response, request)
			if response.Code != http.StatusForbidden || operations.plan != 0 || operations.run != 0 || operations.verify != 0 || len(effective.records) != 1 {
				t.Fatalf("status=%d calls=%d/%d/%d records=%d body=%s", response.Code, operations.plan, operations.run, operations.verify, len(effective.records), response.Body.String())
			}
			record := effective.records[0]
			if record.Decision.Target.Capability != test.capability || record.Decision.Target.ResourceKind != test.kind || record.Decision.Target.ResourceID != test.target {
				t.Fatalf("decision target=%#v", record.Decision.Target)
			}
		})
	}
}

func newRestoreTestApplication(t *testing.T, operations RestoreOperations, effective *effectiveAuthorizationStub) *Application {
	t.Helper()
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}, func() (string, error) { return "request-restore-test", nil })
	app, err := NewApplication(Config{Authority: testAuthority{}, Authorizer: allowOperationAuthorizer(), Reads: testReads{}, Results: factory, Cursors: testCursor{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := RegisterRestoreOperations(app, RestoreConfig{Operations: operations, Results: factory, Authorization: EffectiveAuthorizationConfig{Authorizer: effective, Recorder: effective, Clock: func() time.Time { return time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC) }}}); err != nil {
		t.Fatal(err)
	}
	return app
}

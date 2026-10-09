//go:build linux

package api

import (
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/store"
	"strings"
	"testing"
	"time"
)

// The existing fixture persists canonical production plans, receipts and action
// results. Its OS observations are synthetic and this test never emits evidence.
func TestNativeProducerResolutionRequiresExactStoredReceipt(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	f := replacementPersistedRoleFixture(t, &now, true)
	for _, g := range []struct{ id, op, kind, target string }{{"native-role-author", "gate.evidence.author", "gate", "native.role"}, {"native-role-declaration", "declaration.author", "declaration", "gate-evidence-native-role"}} {
		f.seed.exec(`INSERT INTO effective_authorization_grants VALUES(?,'human-a','control-plane-admin','author',?,?,?,NULL,1,'active','now','now')`, g.id, g.op, g.kind, g.target)
	}
	var receipt generated.ExecutionReceipt
	var raw []byte
	if err := f.db.QueryRow(`SELECT e.canonical_bytes FROM execution_receipts e JOIN immutable_plans p ON p.plan_id=json_extract(e.canonical_bytes,'$.planId') WHERE json_extract(p.canonical_bytes,'$.hostAction.actionId')='debian.role.collect' LIMIT 1`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &receipt); err != nil {
		t.Fatal(err)
	}
	var planRaw []byte
	if err := f.db.QueryRow(`SELECT canonical_bytes FROM immutable_plans WHERE plan_id=?`, receipt.PlanID).Scan(&planRaw); err != nil {
		t.Fatal(err)
	}
	var producerPlan generated.Plan
	if err := json.Unmarshal(planRaw, &producerPlan); err != nil {
		t.Fatal(err)
	}
	if producerPlan.HostAction == nil {
		t.Fatal("missing exact action")
	}
	// The admission fixture predates action-draft and exact input joins. Supply
	// those canonical rows for this stronger native-producer resolver test.
	action := *producerPlan.HostAction
	f.seed.exec(`INSERT INTO host_action_drafts VALUES(?,?,?,'human-a',?,?)`, hostaction.DraftID(action), hostaction.Digest(action), f.seed.bytes(action), action.ExpectedStateRevision, action.RecoveryEpoch)
	for _, op := range producerPlan.Operations {
		if op.OperationID == receipt.OperationID {
			f.seed.exec(`UPDATE plan_run_steps SET input_digest=?,executor_id=? WHERE run_id=? AND step_id=?`, op.InputDigest, op.ExecutorID, receipt.RunID, receipt.StepID)
		}
	}
	rev, err := store.NewPlanRepository(f.authority).CurrentRevision(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	ref := generated.NativeProducerReference{Schema: generated.SchemaIDNativeProducerReference, SchemaVersion: "1.0.0", ScenarioID: "role-application", HostID: f.input.HostID, PlanID: receipt.PlanID, PlanDigest: receipt.PlanDigest, RunID: receipt.RunID, StepID: receipt.StepID, LeaseID: receipt.LeaseID}
	in := generated.NativeCollectRequest{Schema: generated.SchemaIDNativeCollectRequest, SchemaVersion: "1.0.0", ScopeDigest: hostaction.Digest("synthetic-scope"), Stage: "role", EvidenceID: "native-role", ProfileID: f.input.ProfileID, Producers: []generated.NativeProducerReference{ref}, ExpectedStateRevision: rev.StateRevision, RecoveryEpoch: rev.RecoveryEpoch, IdempotencyKey: "native-role"}
	got, err := f.repo.ResolveNativeProducers(f.ctx, in)
	if err != nil || len(got.Executions) != 1 || got.Executions[0].Result == nil || len(got.Measurements) == 0 {
		t.Fatalf("exact producer: executions=%d measurements=%d err=%v", len(got.Executions), len(got.Measurements), err)
	}
	if got.Producers[0].ReceiptDigest != hostaction.BytesDigest(raw) || got.Producers[0].HostIdentityDigest != f.input.HostIdentityDigest {
		t.Fatal("producer binding differs")
	}
	payload := generated.NativeQualification{Schema: generated.SchemaIDNativeQualification, SchemaVersion: "1.0.0", Stage: in.Stage, ScopeDigest: in.ScopeDigest, ProfileID: in.ProfileID, ProfileLockDigest: f.input.ProfileLockDigest, SourceCommit: strings.Repeat("a", 40), SourceDigest: hostaction.Digest("source"), ExecutableDigest: hostaction.Digest("executable"), ControllerInstanceID: got.ControllerInstanceID, RecoveryEpoch: in.RecoveryEpoch, ObservedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), ObserverDigest: hostaction.Digest("synthetic-never-authoritative"), Producers: got.Producers}
	bundle := generated.GateEvidenceBundle{Schema: generated.SchemaIDGateEvidenceBundle, SchemaVersion: "1.1.0", CollectorID: "native-debian-228", ObservedAt: payload.ObservedAt, NativeQualification: &payload, Attachments: []generated.GateEvidenceAttachment{}, Facts: []generated.GateEvidenceFact{{Schema: generated.SchemaIDGateEvidenceFact, SchemaVersion: "1.1.0", FactID: "native.profile-lock", ValueDigest: payload.ProfileLockDigest}, {Schema: generated.SchemaIDGateEvidenceFact, SchemaVersion: "1.1.0", FactID: "native.source", ValueDigest: payload.SourceDigest}}, Checks: []generated.GateEvidenceCheck{{Schema: generated.SchemaIDGateEvidenceCheck, SchemaVersion: "1.1.0", CheckID: "native.role", VerifierVersion: "1.0.0", Result: "passed", ResultDigest: payload.SourceDigest}}}
	if _, err = f.repo.PutNativeGateDraft(f.ctx, store.NativeGateDraftRequest{Request: in, Payload: payload, Bundle: bundle, ResolvedDigest: hostaction.Digest("stale-resolution")}); store.Code(err) != generated.ErrorCodePrerequisiteBlocked {
		t.Fatalf("stale resolution accepted: %v", err)
	}
	var drafts int
	if err = f.db.QueryRow(`SELECT COUNT(*) FROM gate_evidence_drafts WHERE evidence_id=?`, in.EvidenceID).Scan(&drafts); err != nil || drafts != 0 {
		t.Fatalf("denied native write changed authority: %d %v", drafts, err)
	}
	in.Producers[0].LeaseID = "different-lease"
	denied, err := f.repo.ResolveNativeProducers(f.ctx, in)
	if store.Code(err) != generated.ErrorCodePrerequisiteBlocked || len(denied.Executions) != 0 {
		t.Fatalf("substituted lease accepted: %+v %v", denied, err)
	}
}

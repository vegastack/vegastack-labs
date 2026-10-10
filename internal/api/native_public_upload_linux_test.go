//go:build linux

package api

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"net/http"
	"strings"
	"testing"
)

func TestCopiedNativePayloadPublicUploadRemainsFixture(t *testing.T) {
	app, gates, _, _ := gateAPIFixture(t)
	d := "sha256:" + strings.Repeat("a", 64)
	payload := &generated.NativeQualification{Schema: generated.SchemaIDNativeQualification, SchemaVersion: "1.0.0", Stage: "baseline", ScopeDigest: d, ProfileID: "profile-a", ProfileLockDigest: d, SourceCommit: strings.Repeat("a", 40), SourceDigest: d, ExecutableDigest: d, ControllerInstanceID: "controller-a", RecoveryEpoch: 0, ObservedAt: "2026-09-15T08:00:00Z", ExpiresAt: "2026-09-16T08:00:00Z", ObserverDigest: d, Producers: []generated.NativeQualificationProducer{{Schema: generated.SchemaIDNativeQualificationProducer, SchemaVersion: "1.0.0", HostIdentityDigest: d, ReceiptDigest: d, Reference: generated.NativeProducerReference{Schema: generated.SchemaIDNativeProducerReference, SchemaVersion: "1.0.0", ScenarioID: "baseline-access", HostID: "host-a", PlanID: "plan-a", PlanDigest: d, RunID: "run-a", StepID: "step-a", LeaseID: "lease-a"}}}}
	bundle := generated.GateEvidenceBundle{Schema: generated.SchemaIDGateEvidenceBundle, SchemaVersion: "1.1.0", Facts: []generated.GateEvidenceFact{}, Checks: []generated.GateEvidenceCheck{}, Attachments: []generated.GateEvidenceAttachment{}, CollectorID: "native-debian-228", ObservedAt: payload.ObservedAt, NativeQualification: payload}
	in := generated.GateEvidenceRequest{Schema: generated.SchemaIDGateEvidenceRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: 0, RecoveryEpoch: 0, TargetDigest: d, IdempotencyKey: "copied-native", EvidenceID: "copied-native", GateID: "native.baseline", SubjectID: "profile-a", DefinitionVersion: "1.0.0", EvaluatorVersion: "1.0.0", ArtifactDigest: d, ObservedAt: bundle.ObservedAt, Bundle: bundle}
	response := serveGateRequest(t, app, http.MethodPost, "/api/v1/gates/native.baseline/evidence", in)
	if response.Code != http.StatusOK {
		t.Fatalf("copy draft %d %s", response.Code, response.Body)
	}
	draft, err := gates.GetGateDraft(context.Background(), in.EvidenceID)
	if err != nil || draft.SourceKind != "fixture" || draft.ProofClass != "fixture" || draft.Bundle.NativeQualification == nil {
		t.Fatalf("public copy gained native provenance: %#v %v", draft, err)
	}
	applied, err := gates.ListAppliedGateEvidence(context.Background(), in.GateID, in.SubjectID)
	if err != nil || len(applied) != 0 {
		t.Fatalf("upload applied authority: %d %v", len(applied), err)
	}
}

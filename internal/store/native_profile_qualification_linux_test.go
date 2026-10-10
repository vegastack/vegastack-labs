//go:build linux

package store

import (
	"context"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

func nativeProfileReadFixture(t *testing.T) *GateRepository {
	t.Helper()
	r := openGateTestStore(t)
	p := ProfileApplyRequest{BindingID: "native-profile-binding", Scope: GateAppliedProfile{ProfileID: "portable-profile", ProfileVersion: "1.0.0", PolicyID: "portable-policy", PolicyVersion: "1.0.0", Capabilities: []string{}}, Expected: RevisionToken{}, PlanID: "profile-plan", PlanDigest: "sha256:" + strings.Repeat("a", 64), RunID: "profile-run", StepID: "profile-step", LeaseID: "profile-lease", DeclarationID: "profile-declaration", DeclarationRevision: 1, KeyDigest: "sha256:" + strings.Repeat("b", 64), RequestDigest: "sha256:" + strings.Repeat("c", 64), Attribution: audit.Attribution{AuthenticatedPrincipalID: "human-a", AuthenticatedPrincipalMethod: "local"}}
	d, err := r.PutProfileDraft(context.Background(), ProfileDraftRequest{BindingID: p.BindingID, Scope: p.Scope, Expected: p.Expected, KeyDigest: p.KeyDigest, RequestDigest: p.RequestDigest, Attribution: p.Attribution})
	if err != nil {
		t.Fatal(err)
	}
	p.Expected.StateRevision = d.StateRevision
	seedGateExactStep(t, r, p.PlanID, p.PlanDigest, p.RunID, p.StepID, p.LeaseID, p.DeclarationID, p.Scope.ProfileID, d.ScopeDigest, "gate.profile.bind", p.Expected.StateRevision)
	if _, err = r.ApplyProfileBinding(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	// The normal run engine releases its lease after the effect. This finite
	// store fixture supplies that terminal transition before its next operation.
	if _, err = r.store.conn.ExecContext(context.Background(), `UPDATE target_execution_leases SET status='released' WHERE lease_id=?`, p.LeaseID); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestNativeProfileReadRequiresCurrentSelectedScope(t *testing.T) {
	r := nativeProfileReadFixture(t)
	for _, stage := range []string{"baseline", "role", "recovery"} {
		s, err := r.ResolveNativeProfileQualification(context.Background(), "portable-profile", stage)
		if err != nil || s.Profile.ProfileID != "portable-profile" || s.Host.HostID != "" || s.Revision.StateRevision != 2 || len(s.Qualifications) != 0 {
			t.Fatalf("missing evidence must remain unqualified: %+v %v", s, err)
		}
	}
	for _, in := range [][2]string{{"other-profile", "baseline"}, {"portable-profile", "other-stage"}} {
		if _, err := r.ResolveNativeProfileQualification(context.Background(), in[0], in[1]); err == nil {
			t.Fatalf("unselected input accepted: %v", in)
		}
	}
}

func TestNativeProfileReadCannotQualifyPublicFixture(t *testing.T) {
	r := nativeProfileReadFixture(t)
	d := hostaction.Digest("software-fixture-only")
	p := generated.NativeQualification{Schema: generated.SchemaIDNativeQualification, SchemaVersion: "1.0.0", Stage: "baseline", ScopeDigest: d, ProfileID: "portable-profile", ProfileLockDigest: d, SourceCommit: strings.Repeat("a", 40), SourceDigest: d, ExecutableDigest: d, ControllerInstanceID: "fixture-controller", ObservedAt: "2026-09-15T08:00:00Z", ExpiresAt: "2026-09-15T09:00:00Z", ObserverDigest: d, Producers: []generated.NativeQualificationProducer{{Schema: generated.SchemaIDNativeQualificationProducer, SchemaVersion: "1.0.0", Reference: generated.NativeProducerReference{Schema: generated.SchemaIDNativeProducerReference, SchemaVersion: "1.0.0", ScenarioID: "baseline-access", HostID: "fixture-host", PlanID: "fixture-plan", PlanDigest: d, RunID: "fixture-run", StepID: "fixture-step", LeaseID: "fixture-lease"}, HostIdentityDigest: d, ReceiptDigest: d}}}
	in := gateDraftFixture(t)
	in.EvidenceID = "public-native-fixture"
	in.GateID = "native.baseline"
	in.SubjectID = p.ProfileID
	in.Expected.StateRevision = 2
	in.SourceKind = "fixture"
	in.ProofClass = "fixture"
	in.ArtifactDigest = hostaction.Digest(p)
	in.Bundle = generated.GateEvidenceBundle{Schema: generated.SchemaIDGateEvidenceBundle, SchemaVersion: "1.1.0", CollectorID: "native-debian-228", ObservedAt: p.ObservedAt, NativeQualification: &p, Facts: []generated.GateEvidenceFact{{Schema: generated.SchemaIDGateEvidenceFact, SchemaVersion: "1.1.0", FactID: "native.profile-lock", ValueDigest: d}}, Checks: []generated.GateEvidenceCheck{{Schema: generated.SchemaIDGateEvidenceCheck, SchemaVersion: "1.1.0", CheckID: "native.baseline", VerifierVersion: "1.0.0", Result: "passed", ResultDigest: d}}, Attachments: []generated.GateEvidenceAttachment{}}
	draft, err := r.PutGateDraft(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	a := gateApplyFixture(draft)
	a.ReleaseBuildID = "test-build"
	a.ToolVersion = "1.0.0"
	a.ExpiresAt = p.ExpiresAt
	seedGateExactStep(t, r, a.PlanID, a.PlanDigest, a.RunID, a.StepID, a.LeaseID, a.DeclarationID, a.SubjectID, draft.BundleDigest, "gate.evidence.apply", a.Expected.StateRevision)
	if _, err = r.ApplyGateEvidence(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	s, err := r.ResolveNativeProfileQualification(context.Background(), p.ProfileID, p.Stage)
	if err != nil || len(s.Qualifications) != 0 || len(s.NativeProducerBindings) != 0 {
		t.Fatalf("public fixture promoted: %+v %v", s, err)
	}
}

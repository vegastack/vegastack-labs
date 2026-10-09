package hostreplacement

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"testing"
)

func restoreFixture() (generated.HostReplacementRequest, generated.RestoreBinding) {
	in := fixture()
	in.RestorationClass = "control-database"
	source := generated.RestoreSourceBinding{PointID: "point", ManifestDigest: hostaction.BytesDigest([]byte("manifest"))}
	in.Source = &generated.HostReplacementSourceReference{Schema: generated.SchemaIDHostReplacementSourceReference, SchemaVersion: "1.0.0", PointID: source.PointID, ManifestDigest: source.ManifestDigest, SourceBindingDigest: hostaction.Digest(source), CustodyReferenceID: "draft", CustodyBindingDigest: hostaction.BytesDigest([]byte("admission"))}
	b := generated.RestoreBinding{Source: source, FormerHostID: in.OldHostID, ReplacementHostID: in.NewHostID, RecoveryDraftID: "draft", SourceAdmissionDigest: in.Source.CustodyBindingDigest, PriorRecoveryEpoch: in.RecoveryEpoch, NextRecoveryEpoch: in.RecoveryEpoch + 1, PriorInstanceID: "old-controller", NewInstanceID: "new-controller", PlanID: "restore-plan", PlanDigest: hostaction.BytesDigest([]byte("plan")), Status: "verification-required", ReplacementContinuity: &generated.HostReplacementContinuityReference{ReplacementID: in.ReplacementID, SourceBindingDigest: in.Source.SourceBindingDigest}}
	return in, b
}

type restoreCallFixture struct {
	binding generated.RestoreBinding
	calls   int
}

func (s *restoreCallFixture) Run(context.Context, generated.RestoreRunRequest, identity.Principal) (generated.RestoreBinding, error) {
	s.calls++
	return s.binding, nil
}
func (s *restoreCallFixture) Verify(context.Context, generated.RestoreVerifyRequest, identity.Principal) (generated.RestoreVerification, error) {
	panic("stage must not verify before startup")
}
func TestReplacementStageNeverClaimsRecoveredAuthority(t *testing.T) {
	in, b := restoreFixture()
	ops := &restoreCallFixture{binding: b}
	run := generated.RestoreRunRequest{PlanID: b.PlanID, PlanDigest: b.PlanDigest}
	got, e := StageRestore(context.Background(), in, b, run, identity.Principal{}, ops)
	if e != nil || got.Status != "verification-required" || ops.calls != 1 {
		t.Fatalf("%+v %v", got, e)
	}
	ops.binding.Status = "completed"
	if _, e = StageRestore(context.Background(), in, b, run, identity.Principal{}, ops); e == nil {
		t.Fatal("run claimed recovered authority")
	}
	ops.calls = 0
	in.Source.CustodyBindingDigest = hostaction.BytesDigest([]byte("other"))
	if _, e = StageRestore(context.Background(), in, b, run, identity.Principal{}, ops); e == nil || ops.calls != 0 {
		t.Fatal("mismatched custody reached run")
	}
}
func TestReplacementDestinationPreservesCapacityAndIdentity(t *testing.T) {
	in, _ := restoreFixture()
	observed := ReplacementDestination{HostID: in.NewHostID, IdentityDigest: in.NewIdentityDigest, TargetDigest: in.NewTargetDigest, ProfileLockDigest: in.ProfileLockDigest, PreservedPreimageDigest: in.PreservedPreimageDigest, CapacityBytes: 1000, SnapshotBytes: 400, PreservedBytes: 200, FilesystemObservationDigest: "proof", CandidatePreimageDigest: "candidate"}
	if e := ValidateDestination(in, observed); e != nil {
		t.Fatal(e)
	}
	observed.SnapshotBytes++
	if ValidateDestination(in, observed) == nil {
		t.Fatal("insufficient two-copy capacity accepted")
	}
	observed.SnapshotBytes = 400
	observed.IdentityDigest = in.OldIdentityDigest
	if ValidateDestination(in, observed) == nil {
		t.Fatal("old identity destination accepted")
	}
}

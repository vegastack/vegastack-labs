package recovery

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"testing"
)

type continuityGuardFixture struct {
	ref *generated.HostReplacementContinuityReference
	err error
}

func (g continuityGuardFixture) PrepareReplacementContinuity(context.Context, generated.RestoreRequest, VerifiedSource) (*generated.HostReplacementContinuityReference, error) {
	return g.ref, g.err
}

type continuityCapturingPlanner struct {
	*restorePlannerStub
	request generated.RestoreRequest
}

func (p *continuityCapturingPlanner) CreateRestorePlan(ctx context.Context, r generated.RestoreRequest, s VerifiedSource, f FenceResult, a AuditContinuity, i identity.Principal) (generated.RestoreBinding, error) {
	p.request = r
	b, e := p.restorePlannerStub.CreateRestorePlan(ctx, r, s, f, a, i)
	b.ReplacementContinuity = r.ReplacementContinuity
	return b, e
}
func continuityReference() *generated.HostReplacementContinuityReference {
	return &generated.HostReplacementContinuityReference{Schema: generated.SchemaIDHostReplacementContinuityReference, SchemaVersion: "1.0.0", ReplacementID: "replacement", SourcePointID: "point-a", SourceBindingDigest: testCandidateDigest("a"), Digest: testCandidateDigest("b"), SourceAliasHighWatermark: 1, CurrentAliasHighWatermark: 4}
}

func TestReplacementContinuityFlowsThroughRealRestoreOperations(t *testing.T) {
	service, request, planner, _, _ := operationsFixture(t)
	capture := &continuityCapturingPlanner{restorePlannerStub: planner}
	service.config.Plans = capture
	ref := continuityReference()
	service.config.ReplacementContinuity = continuityGuardFixture{ref: ref}
	got, e := service.Plan(context.Background(), request, identity.Principal{ID: "human-a", Method: identity.LocalOSPeerMethod})
	if e != nil {
		t.Fatal(e)
	}
	if !sameJSONValue(got.ReplacementContinuity, ref) || !sameJSONValue(capture.request.ReplacementContinuity, ref) {
		t.Fatal("server-derived continuity omitted from immutable plan")
	}
}
func TestReplacementContinuityRunRejectsOmissionAndStaleSourceBeforeStaging(t *testing.T) {
	for _, mode := range []string{"omitted-binding", "changed-watermark", "missing-guard", "unavailable-source"} {
		t.Run(mode, func(t *testing.T) {
			service, request, planner, sessions, stager := operationsFixture(t)
			ref := continuityReference()
			request.ReplacementContinuity = ref
			planner.qualification.Request = request
			planner.qualification.Binding.ReplacementContinuity = ref
			service.config.ReplacementContinuity = continuityGuardFixture{ref: ref}
			switch mode {
			case "omitted-binding":
				planner.qualification.Binding.ReplacementContinuity = nil
			case "changed-watermark":
				fresh := *ref
				fresh.CurrentAliasHighWatermark++
				service.config.ReplacementContinuity = continuityGuardFixture{ref: &fresh}
			case "missing-guard":
				service.config.ReplacementContinuity = nil
			case "unavailable-source":
				service.config.ReplacementContinuity = continuityGuardFixture{err: ErrWitnessUnavailable}
			}
			run := operationsRunRequest(request, planner.qualification.Binding, "ack-a")
			if _, e := service.Run(context.Background(), run, identity.Principal{ID: "human-a", Method: identity.LocalOSPeerMethod}); e == nil {
				t.Fatal("unsafe restore staged")
			}
			if stager.calls != 0 || len(sessions.transitions) != 0 {
				t.Fatalf("effects before current continuity: %d %v", stager.calls, sessions.transitions)
			}
		})
	}
}
func TestReplacementContinuityMissingGuardCannotPlanReference(t *testing.T) {
	service, request, planner, _, _ := operationsFixture(t)
	request.ReplacementContinuity = continuityReference()
	if _, e := service.Plan(context.Background(), request, identity.Principal{ID: "human-a", Method: identity.LocalOSPeerMethod}); e == nil || planner.created != 0 {
		t.Fatal("reference bypassed absent continuity guard")
	}
}
func TestReplacementSnapshotWatermarkCannotDefaultUnsupportedToZero(t *testing.T) {
	source := VerifiedSource{Binding: generated.RestoreSourceBinding{PointID: "point"}, DatabaseDigest: testCandidateDigest("a"), Snapshot: snapshotStub{}}
	if _, e := InspectVerifiedSourceAliasWatermark(context.Background(), source); e == nil {
		t.Fatal("unsupported source claimed empty alias history")
	}
}

package qualification

import (
	"context"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostreplacement"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

type recoveryNegativeTestAPI struct {
	state        generated.HostReplacementState
	mode         string
	reads, calls int
}

func negativeTestResult(command, code string) generated.RunResult {
	return generated.RunResult{Command: command, RequestID: "request-fixture", Status: "failed", Errors: []generated.ResultError{{Code: code, Target: "host-replacement"}}}
}
func (a *recoveryNegativeTestAPI) GetHostReplacement(_ context.Context, _ serverconfig.Profile, id string) (localapi.TypedResponse[generated.HostReplacementState], error) {
	if id != a.state.ReplacementID {
		x := localapi.TypedResponse[generated.HostReplacementState]{ExitCode: 1, Result: negativeTestResult("api.v1.host-replacements.get", "RESOURCE_NOT_FOUND")}
		if a.mode == "competing-exists" {
			x.ExitCode = 0
		}
		return x, nil
	}
	a.reads++
	v := a.state
	v.AliasBindings = append([]generated.HostReplacementAliasBinding{}, v.AliasBindings...)
	if a.reads > 1 && a.mode == "owner-changed" {
		v.AliasBindings[0].OwnerHostID = "unexpected"
	}
	return localapi.TypedResponse[generated.HostReplacementState]{Data: v, Result: generated.RunResult{StateRevision: 9}}, nil
}
func (a *recoveryNegativeTestAPI) PrepareHostReplacement(_ context.Context, _ serverconfig.Profile, q generated.HostReplacementRequest) (localapi.TypedResponse[generated.HostReplacementSubmission], error) {
	a.calls++
	r := negativeTestResult("api.v1.host-replacements.create", "PLAN_STALE")
	if q.ExpectedStateRevision != 9 {
		panic("did not bind actual read revision")
	}
	if a.mode == "wrong-denial" {
		r.Errors[0].Code = "AUTHORIZATION_DENIED"
	}
	if a.mode == "changed" {
		r.Changed = true
	}
	return localapi.TypedResponse[generated.HostReplacementSubmission]{Result: r, ExitCode: 1}, nil
}
func (a *recoveryNegativeTestAPI) SubmitHostAction(context.Context, serverconfig.Profile, generated.HostActionRequest) (localapi.TypedResponse[generated.HostActionSubmission], error) {
	panic("unexpected host action")
}

func recoveryNegativeRequestFixture() (generated.NativeReplacementRecoveryRequest, generated.HostReplacementState) {
	d := func(s string) string { return hostaction.Digest(s) }
	q := generated.HostReplacementRequest{Schema: generated.SchemaIDHostReplacementRequest, SchemaVersion: "1.0.0", ReplacementID: "replacement-original", Operation: "freeze", RestorationClass: "control-database", OldHostID: "old-host", NewHostID: "new-host", OldIdentityDigest: d("old"), NewIdentityDigest: d("new"), OldTargetDigest: d("old-target"), NewTargetDigest: d("new-target"), OldSSHHostKeyDigest: d("old-key"), NewSSHHostKeyDigest: d("new-key"), OldTargetRevision: 1, NewTargetRevision: 1, ProfileID: "profile", ProfileLockDigest: d("profile"), OldRoleBindingDigest: d("old-role"), RoleDeclarationID: "old-role", RoleDeclarationRevision: 1, ProposedRoleDeclarationID: "new-role", ProposedRoleDeclarationRevision: 1, ProposedRoleBindingDigest: d("new-role"), PreservedPreimageDigest: d("preimage"), AliasBindings: []generated.HostReplacementAliasBinding{{Schema: generated.SchemaIDHostReplacementAliasBinding, SchemaVersion: "1.0.0", AliasID: "alias-a", OwnerHostID: "old-host", OwnerIdentityDigest: d("old"), OwnerRevision: 1, OwnershipGeneration: 1}}, PayloadIDs: []string{}, VolumeIDs: []string{}, ResourceIDs: []string{}, OSPreparation: generated.HostReplacementOsPreparation{Schema: generated.SchemaIDHostReplacementOsPreparation, SchemaVersion: "1.0.0", Method: "administrator-prepared", ObservationID: "observation-a", ObservationDigest: d("observation"), HostIdentityDigest: d("new"), ConfirmedAt: "2026-10-09T12:00:00Z"}, ExpectedStateRevision: 1, IdempotencyKey: "freeze-competing", Source: &generated.HostReplacementSourceReference{Schema: generated.SchemaIDHostReplacementSourceReference, SchemaVersion: "1.0.0", PointID: "point", CustodyReferenceID: "custody", ManifestDigest: d("manifest"), SourceBindingDigest: d("source"), CustodyBindingDigest: d("custody")}}
	binding := hostreplacement.BindingDigest(q)
	plan, run := "freeze-plan", "freeze-run"
	s := generated.HostReplacementState{Schema: generated.SchemaIDHostReplacementState, SchemaVersion: "1.0.0", ReplacementID: q.ReplacementID, DeclarationID: "freeze-declaration", OldHostID: q.OldHostID, NewHostID: q.NewHostID, BindingDigest: binding, OldIdentityDigest: q.OldIdentityDigest, NewIdentityDigest: q.NewIdentityDigest, RoleBindingDigest: q.ProposedRoleBindingDigest, DeclarationRevision: 2, PriorOwnershipGeneration: 1, ProposedOwnershipGeneration: 2, StateRevision: 9, Status: "frozen", RestorationClass: "control-database", AliasBindings: append([]generated.HostReplacementAliasBinding{}, q.AliasBindings...), NextAction: "resolve-fences", Blockers: []string{}, PlanID: &plan, RunID: &run, FreezeEventDigest: d("freeze")}
	s.AliasBindings[0].OwnerRevision++
	q.ReplacementID = "replacement-competing"
	return generated.NativeReplacementRecoveryRequest{Schema: generated.SchemaIDNativeReplacementRecoveryRequest, SchemaVersion: "1.0.0", Kind: "concurrent-replacement", ReplacementID: s.ReplacementID, BindingDigest: binding, Replacement: &q}, s
}

func TestRecoveryNegativeUsesActualAPIResponsesAndRereadsOwnership(t *testing.T) {
	for _, mode := range []string{"complete", "wrong-denial", "changed", "competing-exists", "owner-changed"} {
		t.Run(mode, func(t *testing.T) {
			request, state := recoveryNegativeRequestFixture()
			api := &recoveryNegativeTestAPI{state: state, mode: mode}
			out, err := executeReplacementNegative(context.Background(), api, serverconfig.Profile{}, request)
			if mode == "complete" {
				if err != nil || api.reads != 2 || api.calls != 1 || out.Response == nil || out.CompetingLookup == nil {
					t.Fatalf("observed pipeline %+v %v reads=%d calls=%d", out, err, api.reads, api.calls)
				}
			} else if err == nil {
				t.Fatal("wrong/mutating response accepted")
			}
		})
	}
}

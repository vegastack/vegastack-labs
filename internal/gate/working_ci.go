package gate

import (
	"context"
	"slices"
	"time"

	"github.com/vegastack/vegastack-labs/internal/debianaccess"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// WorkingCIDecision is deliberately not native qualification or general host
// admission. Only the CI demonstration and its CI role preparation consume it.
type WorkingCIDecision struct {
	Mode, Stage, Outcome, ReasonCode, SnapshotDigest string
	ControlDigests                                   map[string]string
	Deferred                                         []string
}

// WorkingCISelected requires an explicit, versioned, host-scoped applied policy.
// Selection alone grants nothing: evaluation checks the authoritative binding.
func WorkingCISelected(s store.HostAdmissionSnapshot) bool {
	p := s.AppliedProfile
	return p != nil && p.ProfileID == "vegastack-labs" && p.ProfileVersion == "1.0.0" &&
		p.PolicyID == "labs-working-ci" && p.PolicyVersion == "1.0.0" &&
		slices.Contains(p.Capabilities, "ci.working-demonstration") &&
		slices.Contains(p.Capabilities, "ci.working-host."+s.Host.HostID)
}

// EvaluateWorkingCI reuses joined, applied action receipts and their existing
// control/probe verification. It never creates native evidence or changes the
// strict host admission evaluator. Empty storage is explicit non-applicability,
// not a passing encryption result; any declared volume blocks this policy.
func EvaluateWorkingCI(ctx context.Context, s store.HostAdmissionSnapshot, scope ResolvedScope, stage string, at time.Time) (WorkingCIDecision, error) {
	out := WorkingCIDecision{Mode: "labs-working-ci/1.0.0", Stage: stage, Outcome: "blocked", ReasonCode: "working-policy-not-selected", ControlDigests: map[string]string{}, Deferred: []string{"full-native-qualification", "encrypted-storage-not-selected"}}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if !WorkingCISelected(s) {
		return out, nil
	}
	deny := func(reason string) (WorkingCIDecision, error) { out.ReasonCode = reason; return out, nil }
	p := s.AppliedProfile
	if s.AppliedProfileDigest != hostaction.Digest(*p) ||
		p.ProfileID != scope.ProfileID || p.ProfileVersion != scope.ProfileVersion || p.PolicyID != scope.PolicyID || p.PolicyVersion != scope.PolicyVersion ||
		p.StateRevision != scope.StateRevision || p.RecoveryEpoch != scope.RecoveryEpoch || hostaction.Digest(p.Capabilities) != hostaction.Digest(scope.Capabilities) ||
		p.StateRevision <= 0 || p.StateRevision > s.Revision.StateRevision || p.RecoveryEpoch != s.Revision.RecoveryEpoch {
		return deny("working-policy-binding-changed")
	}
	if stage != "baseline" && stage != "role" || stage == "baseline" && s.Profile.RoleID != "host" && s.Profile.RoleID != "ci" || stage == "role" && s.Profile.RoleID != "ci" ||
		debianaccess.ProtectedName(s.Host.HostID) || !slices.Contains([]string{"physical", "qualified-virtual"}, s.Host.IdentityClass) || s.Host.Status != "adopted-unadmitted" {
		return deny("working-ci-scope-invalid")
	}
	v := hostProofVerifier{snapshot: s, scope: scope, at: at.UTC()}
	if reason := v.validateSnapshot(); reason != "" {
		return deny(reason)
	}
	if s.HasVolumeDeclarations || len(s.VolumeIDs) != 0 {
		return deny("working-ci-volume-declared")
	}
	if stage == "role" && (s.RoleBindingDigest == "" || len(s.RoleBlockers) != 0) {
		return deny("working-ci-role-binding-missing")
	}
	stages := []string{"baseline"}
	if stage == "role" {
		stages = append(stages, "role")
	}
	for _, selected := range stages {
		controls, err := RequiredHostControls(s.Profile, selected)
		if err != nil {
			return deny("host-platform-unqualified")
		}
		for _, id := range controls {
			req, ok := hostRequirement(s.Profile.RoleID, id, selected)
			if !ok {
				return deny("host-control-missing")
			}
			if req.Applicability == "volumes" {
				continue
			}
			if !v.applicable(req) {
				continue
			}
			digest, reason := v.controlDigest(req)
			if reason != "" {
				return deny(reason + ":" + id)
			}
			out.ControlDigests[selected+":"+id] = digest
		}
	}
	out.Outcome = "passed"
	out.ReasonCode = "working-ci-only-full-qualification-deferred"
	out.SnapshotDigest = store.HostAdmissionSnapshotDigest(s)
	return out, nil
}

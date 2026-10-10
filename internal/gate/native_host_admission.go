package gate

import (
	"regexp"
	"slices"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// NativeHostObservation retains only the concrete observer's bounded console
// and process observation. Secret/credential witness shapes are never projected.
func NativeHostObservation(o generated.NativeObservation) generated.NativeHostObservation {
	return generated.NativeHostObservation{Schema: generated.SchemaIDNativeHostObservation, SchemaVersion: "1.0.0", Binding: o.Binding, BootID: o.BootID, QEMUPID: o.QEMUPID, QEMUStartTimeTicks: o.QEMUStartTimeTicks, ExecutableDigest: o.ExecutableDigest, DiskDigest: o.DiskDigest, FirmwareDigest: o.FirmwareDigest, ObservedAt: o.ObservedAt, ProcessState: o.ProcessState, ConsoleState: o.ConsoleState, ChannelDigest: o.ChannelDigest}
}

// NativeHostAdmissionBundle derives checks from the same joined measurements
// used by the owning admission evaluator. It is inert until ordinary apply.
func NativeHostAdmissionBundle(s store.HostAdmissionSnapshot, q generated.NativeQualification, scope generated.QualificationScope, observation generated.NativeHostObservation, discoveryDigest, gateID string, at time.Time) (generated.NativeHostProof, []generated.GateEvidenceFact, []generated.GateEvidenceCheck, error) {
	var zero generated.NativeHostProof
	deny := func() (generated.NativeHostProof, []generated.GateEvidenceFact, []generated.GateEvidenceCheck, error) {
		return zero, nil, nil, errNativeProvenance
	}
	roleGate := gateID == "host.role-admission" && q.Stage == "role"
	baselineGate := slices.Contains([]string{"platform-safety", "host.hardening-baseline"}, gateID) && q.Stage == "baseline"
	if (!roleGate && !baselineGate) || s.Host.IdentityClass != "qualified-virtual" || len(s.Blockers) != 0 || s.Host.RecoveryEpoch != q.RecoveryEpoch || s.Revision.RecoveryEpoch != q.RecoveryEpoch || s.Profile.ProfileID != q.ProfileID || s.ProfileLockDigest != q.ProfileLockDigest || discoveryDigest == "" || !validHostJSON(generated.SchemaIDQualificationScope, scope) || !validHostJSON(generated.SchemaIDNativeHostObservation, observation) {
		return deny()
	}
	if hostaction.Digest(scope) != q.ScopeDigest || scope.ProfileID != q.ProfileID || scope.ProfileLockDigest != q.ProfileLockDigest || scope.SourceCommit != q.SourceCommit || scope.ExecutableDigest != q.ExecutableDigest || observation.Binding.ScopeDigest != q.ScopeDigest || observation.Binding.ControllerInstanceID != scope.ControllerInstanceID || observation.Binding.RecoveryEpoch != q.RecoveryEpoch || observation.ExecutableDigest != q.ExecutableDigest || observation.ChannelDigest != scope.ConsoleReferenceDigest || observation.ProcessState != "running" || observation.ConsoleState != "healthy" || !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).MatchString(observation.BootID) {
		return deny()
	}
	observed, e := time.Parse(time.RFC3339, q.ObservedAt)
	actual, a := time.Parse(time.RFC3339, observation.ObservedAt)
	issued, i := time.Parse(time.RFC3339, scope.IssuedAt)
	expires, x := time.Parse(time.RFC3339, scope.ExpiresAt)
	deadline, d := time.Parse(time.RFC3339, observation.Binding.Deadline)
	if e != nil || a != nil || i != nil || x != nil || d != nil || actual.After(observed.Add(time.Second)) || observed.Sub(actual) > 30*time.Second || actual.Before(issued) || !observed.Before(expires) || !expires.After(issued) || expires.Sub(issued) > 4*time.Hour || !actual.Before(deadline) || deadline.Sub(actual) > 30*time.Second {
		return deny()
	}
	guests := 0
	for _, g := range scope.Guests {
		if g.HostID == s.Host.HostID && g.HostIdentityDigest == s.IdentityDigest && g.GuestID == observation.Binding.GuestID && g.DiskDigest == observation.DiskDigest && g.FirmwareDigest == observation.FirmwareDigest {
			guests++
		}
	}
	if guests != 1 {
		return deny()
	}
	joined := false
	b := observation.Binding
	for _, m := range s.Measurements {
		if m.Control.HostID == s.Host.HostID && m.Receipt.Status == "succeeded" && m.Plan.PlanID == b.PlanID && m.Plan.PlanDigest == b.PlanDigest && m.Receipt.RunID == b.RunID && m.Receipt.StepID == b.StepID && m.Receipt.LeaseID == b.LeaseID && m.Receipt.RecoveryEpoch == q.RecoveryEpoch {
			joined = true
		}
	}
	if !joined {
		return deny()
	}
	controls, err := RequiredHostControls(s.Profile, q.Stage)
	if err != nil {
		return deny()
	}
	v := hostProofVerifier{snapshot: s, at: at.UTC()}
	checks := []generated.GateEvidenceCheck{{Schema: generated.SchemaIDGateEvidenceCheck, SchemaVersion: "1.1.0", CheckID: "native." + q.Stage, VerifierVersion: "1.0.0", Result: "passed", ResultDigest: q.SourceDigest}}
	recoveryDigest, recoveryErr := HostControlProofDigest(s, "host.ssh-effective", "baseline", at)
	if recoveryErr != nil {
		return deny()
	}
	for _, id := range controls {
		req, ok := hostRequirement(s.Profile.RoleID, id, q.Stage)
		if !ok {
			return deny()
		}
		if !v.applicable(req) {
			continue
		}
		digest, reason := v.controlDigest(req)
		if reason != "" {
			return deny()
		}
		if id == "host.ssh-effective" {
			recoveryDigest = digest
		}
		if gateID == "host.hardening-baseline" || roleGate {
			checks = append(checks, generated.GateEvidenceCheck{Schema: generated.SchemaIDGateEvidenceCheck, SchemaVersion: "1.1.0", CheckID: id, VerifierVersion: "1.0.0", Result: "passed", ResultDigest: digest})
		}
	}
	if recoveryDigest == "" {
		return deny()
	}
	proof := generated.NativeHostProof{Schema: generated.SchemaIDNativeHostProof, SchemaVersion: "1.0.0", HostID: s.Host.HostID, HostIdentityDigest: s.IdentityDigest, HostBindingDigest: s.BindingDigest, DiscoveryDigest: discoveryDigest, ControlsDigest: store.NativeHostControlsDigest(s), RecoveryAccessDigest: recoveryDigest, Scope: scope, Observation: observation}
	if gateID == "platform-safety" {
		for _, prerequisite := range NativeHostPrerequisites(proof) {
			checks = append(checks, generated.GateEvidenceCheck{Schema: generated.SchemaIDGateEvidenceCheck, SchemaVersion: "1.1.0", CheckID: prerequisite.ID, VerifierVersion: "1.0.0", Result: "passed", ResultDigest: prerequisite.Digest})
		}
	}
	facts := []generated.GateEvidenceFact{}
	for _, f := range []struct{ id, digest string }{{"native.profile-lock", q.ProfileLockDigest}, {"native.source", q.SourceDigest}, {"host.binding", s.BindingDigest}, {"host.profile-lock", s.ProfileLockDigest}} {
		facts = append(facts, generated.GateEvidenceFact{Schema: generated.SchemaIDGateEvidenceFact, SchemaVersion: "1.1.0", FactID: f.id, ValueDigest: f.digest})
	}
	if roleGate {
		if s.RoleBindingDigest == "" || len(s.RoleBlockers) != 0 {
			return deny()
		}
		facts = append(facts, generated.GateEvidenceFact{Schema: generated.SchemaIDGateEvidenceFact, SchemaVersion: "1.1.0", FactID: "host.role-binding", ValueDigest: s.RoleBindingDigest})
	}
	return proof, facts, checks, nil
}

func NativeHostPrerequisites(proof generated.NativeHostProof) []store.HostPrerequisiteProof {
	out := []store.HostPrerequisiteProof{}
	for _, id := range []string{"identity-console", "recovery-access", "qualified-virtual"} {
		digest := hostaction.Digest(struct {
			ID    string
			Proof generated.NativeHostProof
		}{id, proof})
		out = append(out, store.HostPrerequisiteProof{ID: id, Digest: digest})
	}
	return out
}

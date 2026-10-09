package gate

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/debianaccess"
	"github.com/vegastack/vegastack-labs/internal/debianbaseline"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/linuxrole"
	"github.com/vegastack/vegastack-labs/internal/store"
	"slices"
	"time"
)

type hostProofVerifier struct {
	snapshot store.HostAdmissionSnapshot
	scope    ResolvedScope
	at       time.Time
}
type hostEvidenceReader struct{ rows []generated.GateEvidence }

func (r hostEvidenceReader) ListAppliedGateEvidence(_ context.Context, gateID, subjectID string) ([]generated.GateEvidence, error) {
	out := []generated.GateEvidence{}
	for _, e := range r.rows {
		if e.GateID == gateID && e.SubjectID == subjectID {
			out = append(out, e)
		}
	}
	return out, nil
}

// EvaluateHostAdmission accepts only the internal authoritative snapshot. There
// is no client-provided registry or alternative admission decision in store.
func EvaluateHostAdmission(ctx context.Context, snapshot store.HostAdmissionSnapshot, scope ResolvedScope, gateID string, at time.Time) (generated.GateEvaluation, error) {
	if e := ctx.Err(); e != nil {
		return generated.GateEvaluation{}, e
	}
	if gateID == "host.role-admission" {
		snapshot.Blockers = append(append([]string{}, snapshot.Blockers...), snapshot.RoleBlockers...)
	}
	v := &hostProofVerifier{snapshot: snapshot, scope: scope, at: at.UTC()}
	registry := NewProofRegistry()
	for _, id := range []string{"platform-safety", "host.hardening-baseline", "host.role-admission"} {
		for _, source := range []string{"local", "independent"} {
			registry.Register(id, source, v)
		}
	}
	subject := Subject{ID: snapshot.Host.HostID, Kind: "node", ToolVersion: snapshot.ProfileLock.ExecutableVersion, StateRevision: snapshot.Revision.StateRevision, DeclarationID: snapshot.DeclarationID, DeclarationRevision: snapshot.DeclarationRevision, ArtifactDigest: snapshot.BindingDigest}
	state := newEvaluationContext(hostEvidenceReader{snapshot.Evidence}, scope, subject, at, registry)
	state.host = v
	if gateID != "host.hardening-baseline" && gateID != "host.role-admission" && gateID != "platform-safety" {
		return state.base(gateID, Definition{}), errHostAdmission
	}
	if reason := v.validateSnapshot(); reason != "" {
		out := state.base(gateID, state.definitions[gateID].Definition)
		out.Outcome = "blocked"
		out.ReasonCode = reason
		return out, nil
	}
	return state.check(ctx, gateID)
}
func (v *hostProofVerifier) validateSnapshot() string {
	s := v.snapshot
	for _, reason := range s.Blockers {
		switch reason {
		case "host-control-missing", "host-binding-changed", "host-qualification-missing", "host-prerequisite-missing", "host-platform-unqualified":
			return reason
		default:
			return "host-binding-changed"
		}
	}
	if v.at.IsZero() || s.Host.HostID == "" || s.IdentityDigest == "" || s.BindingDigest == "" || s.DeclarationID == "" || s.DeclarationRevision <= 0 || s.Host.RecoveryEpoch != s.Revision.RecoveryEpoch || v.scope.RecoveryEpoch != s.Revision.RecoveryEpoch || v.scope.StateRevision > s.Revision.StateRevision {
		return "host-binding-changed"
	}
	if s.ProfileLockDigest != hostaction.Digest(s.ProfileLock) || s.Profile.OSFamily != s.ProfileLock.OSFamily || s.Profile.OSVersion != s.ProfileLock.OSVersion || s.Profile.Architecture != s.ProfileLock.Architecture {
		return "host-binding-changed"
	}
	if _, e := RequiredHostControls(s.Profile, "baseline"); e != nil {
		return "host-platform-unqualified"
	}
	if len(s.Results) > 256 || len(s.Measurements) > 256 || len(s.Evidence) > 64 || len(s.PrerequisiteDigests) > 16 || len(s.VolumeIDs) > 16 {
		return "host-binding-changed"
	}
	return ""
}
func (v *hostProofVerifier) validateEvidence(def Definition, e generated.GateEvidence) string {
	if !validHostJSON(generated.SchemaIDGateEvidence, e) || e.SchemaVersion != "1.1.0" || e.Status != "applied" || e.ProofClass != "live" || (e.SourceKind != "local" && e.SourceKind != "independent") {
		return "host-evidence-invalid"
	}
	s := v.snapshot
	b, ok := s.AppliedBindings[e.EvidenceID]
	if !ok || e.SubjectID != s.Host.HostID || e.GateID != def.ID || e.RecoveryEpoch != s.Revision.RecoveryEpoch || b.RecoveryEpoch != e.RecoveryEpoch || e.StateRevision <= 0 || e.StateRevision > s.Revision.StateRevision || b.StateRevision != e.StateRevision || e.DeclarationID != b.DeclarationID || e.DeclarationRevision != b.DeclarationRevision || e.ArtifactDigest != b.ArtifactDigest || e.BundleDigest != b.BundleDigest {
		return "host-binding-changed"
	}
	if e.DefinitionVersion != def.Version || e.EvaluatorVersion != def.EvaluatorVersion || e.ToolVersion != s.ProfileLock.ExecutableVersion || e.ReleaseBuildID == "" || e.ReleaseBuildID != b.ReleaseBuildID || e.ToolVersion != b.ToolVersion || e.ProfileID != v.scope.ProfileID || e.ProfileVersion != v.scope.ProfileVersion || e.PolicyID != v.scope.PolicyID || e.PolicyVersion != v.scope.PolicyVersion {
		return "host-binding-changed"
	}
	observed, _ := time.Parse(time.RFC3339, e.ObservedAt)
	if !hostEvidenceTime(e, v.at) || (def.FreshnessSeconds > 0 && v.at.Sub(observed) > time.Duration(def.FreshnessSeconds)*time.Second) {
		return "host-evidence-stale"
	}
	bundle, ok := s.Bundles[e.EvidenceID]
	if !ok || !validHostJSON(generated.SchemaIDGateEvidenceBundle, bundle) || hostaction.Digest(bundle) != e.BundleDigest || bundle.CollectorID != e.CollectorID || bundle.ObservedAt != e.ObservedAt {
		return "host-evidence-invalid"
	}
	return ""
}
func hostEvidenceTime(e generated.GateEvidence, at time.Time) bool {
	observed, x := time.Parse(time.RFC3339, e.ObservedAt)
	applied, y := time.Parse(time.RFC3339, e.AppliedAt)
	expires, z := time.Parse(time.RFC3339, e.ExpiresAt)
	return x == nil && y == nil && z == nil && !observed.After(applied) && !applied.After(at) && !observed.After(at) && expires.After(at) && expires.After(applied) && at.Sub(observed) <= 86400*time.Second
}
func validHostJSON(schema string, value any) bool {
	b, e := json.Marshal(value)
	return e == nil && generated.ValidateContractJSON(schema, b, generated.ContractExact) == nil
}
func (v *hostProofVerifier) Verify(ctx context.Context, def Definition, e generated.GateEvidence) (ProofResult, error) {
	if err := ctx.Err(); err != nil {
		return ProofResult{}, err
	}
	denied := func(reason string) (ProofResult, error) { return ProofResult{ReasonCode: reason}, nil }
	if reason := v.validateEvidence(def, e); reason != "" {
		return denied(reason)
	}
	bundle := v.snapshot.Bundles[e.EvidenceID]
	if !hostFact(bundle, "host.binding", v.snapshot.BindingDigest) || !hostFact(bundle, "host.profile-lock", v.snapshot.ProfileLockDigest) {
		return denied("host-binding-changed")
	}
	if def.ID == "platform-safety" {
		if reason := v.prerequisites(); reason != "" {
			return denied(reason)
		}
		return ProofResult{Verified: true}, nil
	}
	stage := "baseline"
	if def.ID == "host.role-admission" {
		stage = "role"
		if v.snapshot.RoleBindingDigest == "" || !hostFact(bundle, "host.role-binding", v.snapshot.RoleBindingDigest) {
			return denied("host-role-binding-missing")
		}
	}
	if !v.qualified(stage) {
		return denied("host-qualification-missing:" + stage)
	}
	controls, err := RequiredHostControls(v.snapshot.Profile, stage)
	if err != nil {
		return denied("host-platform-unqualified")
	}
	for _, id := range controls {
		req, ok := hostRequirement(v.snapshot.Profile.RoleID, id, stage)
		if !ok {
			return denied("host-control-missing")
		}
		if !v.applicable(req) {
			continue
		}
		digest, reason := v.controlDigest(req)
		if reason != "" {
			return denied(reason + ":" + id)
		}
		if !hostCheck(bundle, id, digest) {
			return denied("host-control-evidence-mismatch:" + id)
		}
	}
	return ProofResult{Verified: true}, nil
}
func hostFact(b generated.GateEvidenceBundle, id, digest string) bool {
	count := 0
	for _, f := range b.Facts {
		if f.FactID == id {
			if f.ValueDigest != digest {
				return false
			}
			count++
		}
	}
	return count == 1
}
func hostCheck(b generated.GateEvidenceBundle, id, digest string) bool {
	count := 0
	for _, c := range b.Checks {
		if c.CheckID == id {
			if c.Result != "passed" || c.VerifierVersion != "1.0.0" || c.ResultDigest != digest {
				return false
			}
			count++
		}
	}
	return count == 1
}
func hostRequirement(role, id, stage string) (generated.HostControlRequirement, bool) {
	for _, r := range generated.GeneratedHostControlRequirements {
		if r.ControlID == id && r.Stage == stage && slices.Contains(r.Roles, role) {
			return r, true
		}
	}
	return generated.HostControlRequirement{}, false
}
func (v *hostProofVerifier) applicable(r generated.HostControlRequirement) bool {
	switch r.Applicability {
	case "always", "volumes":
		return true
	case "networking":
		return slices.Contains([]string{"control", "application", "ci"}, v.snapshot.Profile.RoleID) || v.snapshot.NetworkingRequired
	case "standby":
		return !slices.Contains([]string{"reserve", "recovery-spare"}, v.snapshot.Profile.RoleID) || v.snapshot.StandbyRequired
	}
	return true
}
func (v *hostProofVerifier) currentEvidence(id string) (generated.GateEvidence, bool) {
	var got generated.GateEvidence
	found := false
	for _, e := range v.snapshot.Evidence {
		if e.SupersedesEvidenceID != nil && *e.SupersedesEvidenceID == id || e.RevokesEvidenceID != nil && *e.RevokesEvidenceID == id {
			return got, false
		}
		if e.EvidenceID == id {
			if found {
				return got, false
			}
			got = e
			found = true
		}
	}
	if !found || got.Status != "applied" {
		return got, false
	}
	return got, true
}
func (v *hostProofVerifier) qualified(stage string) bool {
	// Select the authoritative latest native proof before considering positive projections.
	var latest *generated.GateEvidence
	for i := range v.snapshot.Evidence {
		e := &v.snapshot.Evidence[i]
		b, ok := v.snapshot.Bundles[e.EvidenceID]
		if !ok || e.SubjectID != v.snapshot.Host.HostID || e.RecoveryEpoch != v.snapshot.Revision.RecoveryEpoch || !hostFact(b, "native.profile-lock", v.snapshot.ProfileLockDigest) {
			continue
		}
		matches := false
		for _, check := range b.Checks {
			if check.CheckID == "native."+stage {
				matches = true
			}
		}
		if !matches {
			continue
		}
		if latest != nil && e.StateRevision == latest.StateRevision && e.AppliedAt == latest.AppliedAt && e.EvidenceID != latest.EvidenceID {
			return false
		}
		if latest == nil || e.StateRevision > latest.StateRevision || e.StateRevision == latest.StateRevision && e.AppliedAt > latest.AppliedAt {
			latest = e
		}
	}
	if latest == nil {
		return false
	}
	for _, q := range v.snapshot.Qualifications {
		if q.EvidenceID != latest.EvidenceID || q.Stage != stage || q.ProfileDigest != v.snapshot.ProfileLockDigest || q.RecoveryEpoch != v.snapshot.Revision.RecoveryEpoch || q.SourceDigest == "" {
			continue
		}
		e, ok := v.currentEvidence(q.EvidenceID)
		if !ok {
			continue
		}
		def := Definition{ID: e.GateID, Version: e.DefinitionVersion, EvaluatorVersion: e.EvaluatorVersion}
		if v.validateEvidence(def, e) != "" {
			continue
		}
		observed, x := time.Parse(time.RFC3339, q.ObservedAt)
		expires, y := time.Parse(time.RFC3339, q.ExpiresAt)
		if x != nil || y != nil || observed.After(v.at) || v.at.Sub(observed) > 24*time.Hour || !expires.After(v.at) {
			continue
		}
		b := v.snapshot.Bundles[e.EvidenceID]
		if !hostFact(b, "native.profile-lock", q.ProfileDigest) || !hostFact(b, "native.source", q.SourceDigest) || !hostCheck(b, "native."+stage, q.SourceDigest) {
			continue
		}
		if !slices.Contains(v.snapshot.QualificationDigests, e.BundleDigest) {
			continue
		}
		return true
	}
	return false
}
func (v *hostProofVerifier) prerequisites() string {
	keys := []string{"identity-console", "recovery-access"}
	switch v.snapshot.Host.IdentityClass {
	case "physical":
		keys = append(keys, "physical-capacity", "physical-thermal-power")
	case "qualified-virtual":
		keys = append(keys, "qualified-virtual")
	default:
		return "host-prerequisite-missing"
	}
	for _, key := range keys {
		digest := v.snapshot.PrerequisiteDigests[key]
		id := v.snapshot.PrerequisiteEvidenceIDs[key]
		if digest == "" || id == "" {
			return "host-prerequisite-missing:" + key
		}
		e, ok := v.currentEvidence(id)
		if !ok {
			return "host-prerequisite-missing:" + key
		}
		if v.validateEvidence(Definition{ID: e.GateID, Version: e.DefinitionVersion, EvaluatorVersion: e.EvaluatorVersion}, e) != "" {
			return "host-prerequisite-missing:" + key
		}
		b := v.snapshot.Bundles[id]
		if !hostFact(b, "host.binding", v.snapshot.BindingDigest) || !hostCheck(b, key, digest) {
			return "host-prerequisite-missing:" + key
		}
	}
	return ""
}

func (v *hostProofVerifier) measurement(id string) (store.HostAdmissionMeasurement, string) {
	var out store.HostAdmissionMeasurement
	found := false
	for _, c := range v.snapshot.Results {
		if c.ControlID != id {
			continue
		}
		if found {
			return out, "host-control-conflict"
		}
		found = true
		matches := 0
		for _, m := range v.snapshot.Measurements {
			if hostaction.Digest(m.Control) == hostaction.Digest(c) {
				out = m
				matches++
			}
		}
		if matches != 1 {
			return out, "host-control-missing"
		}
	}
	if !found {
		return out, "host-control-missing"
	}
	if reason := v.validateMeasurement(out); reason != "" {
		return out, reason
	}
	return out, ""
}
func (v *hostProofVerifier) validateMeasurement(x store.HostAdmissionMeasurement) string {
	s := v.snapshot
	c, m, r, p, receipt := x.Control, x.Measurement, x.Result, x.Plan, x.Receipt
	raw, _ := json.Marshal(c)
	if _, e := DecodeHostControlResult(raw); e != nil {
		return "host-control-invalid"
	}
	if c.HostID != s.Host.HostID || c.IdentityDigest != s.IdentityDigest || c.IdentityClass != s.Host.IdentityClass || c.ProfileID != s.Profile.ProfileID || c.OSFamily != s.Profile.OSFamily || c.OSVersion != s.Profile.OSVersion || c.OSBuild != nil || c.Architecture != s.Profile.Architecture || c.BaselineVersion != "1.0.0" || c.RecoveryEpoch != s.Revision.RecoveryEpoch || c.ProducerVersion != "1.0.0" {
		return "host-binding-changed"
	}
	if c.RoleID != s.Profile.RoleID && !(c.ProducerID == "debian-access-native" && c.RoleID == "host") && !(c.ProducerID == "debian-access-probe" && c.RoleID == "host") {
		return "host-binding-changed"
	}
	at, e := time.Parse(time.RFC3339, c.ObservedAt)
	if e != nil || at.After(v.at) || v.at.Sub(at) > 24*time.Hour {
		return "host-control-stale"
	}
	if c.Status != "passed" || m.Status != "passed" {
		return "host-control-failed"
	}
	if hostaction.ValidateResult(r) != nil || r.ResultDigest != hostaction.ResultDigest(r) || r.Status != "succeeded" || !r.EffectObserved || receipt.Status != "succeeded" || receipt.ResultDigest != r.ResultDigest || !validHostJSON(generated.SchemaIDExecutionReceipt, receipt) {
		return "host-control-invalid"
	}
	if hostaction.Digest(receipt) != c.ActionReceiptDigest || !slices.Contains(s.ActionReceiptDigests, c.ActionReceiptDigest) || receipt.RecoveryEpoch != s.Revision.RecoveryEpoch || receipt.PlanID != p.PlanID || receipt.PlanDigest != p.PlanDigest || c.DeclarationID != p.DeclarationID || c.DeclarationRevision != p.Binding.DeclarationRevision || p.Binding.RecoveryEpoch != s.Revision.RecoveryEpoch || p.Binding.StateRevision > s.Revision.StateRevision {
		return "host-binding-changed"
	}
	if m.MeasurementDigest != hostaction.MeasurementDigest(m) || m.MeasurementDigest != c.MeasurementDigest || m.BundleDigest != r.BundleDigest || m.SubjectHostID != c.HostID || m.SubjectIdentityDigest != c.IdentityDigest || m.ProfileLockDigest != s.ProfileLockDigest || m.ControlID != c.ControlID || m.ProducerID != c.ProducerID || m.ProducerVersion != c.ProducerVersion || m.ObservedAt != c.ObservedAt || m.PositiveProbeDigest != c.PositiveProbeDigest || m.NegativeProbeDigest != c.NegativeProbeDigest {
		return "host-control-invalid"
	}
	found := 0
	for _, a := range r.ControlMeasurements {
		if hostaction.Digest(a) == hostaction.Digest(m) {
			found++
		}
	}
	if found != 1 {
		return "host-control-invalid"
	}
	opFound := false
	for _, op := range p.Operations {
		if op.OperationID == receipt.OperationID && op.TargetID == receipt.TargetID && op.ArtifactDigest == receipt.ArtifactDigest {
			opFound = true
		}
	}
	if !opFound {
		return "host-control-invalid"
	}
	if c.ProducerID == "linux-role" {
		if m.Kind != "role" || m.Role == nil || m.Baseline != nil || m.Volume != nil || m.Probe != nil || m.Role.RoleID != s.Profile.RoleID || m.Role.RoleBindingDigest != s.RoleBindingDigest || m.Role.Verification == "unavailable" || p.HostAction == nil {
			return "host-control-invalid"
		}
		a := p.HostAction
		roleScope, err := linuxrole.ScopeForRequest(*a)
		if err != nil || roleScope == nil || p.HostRoleScope == nil || hostaction.Digest(roleScope) != hostaction.Digest(p.HostRoleScope) || roleScope.RoleBindingDigest != s.RoleBindingDigest {
			return "host-control-invalid"
		}
		if !linuxrole.IsAction(a.ActionID) || a.HostID != s.Host.HostID || a.ActionInputDigest != hostaction.BytesDigest([]byte(a.ActionInput)) || m.ConfigurationDigest != a.ActionInputDigest {
			return "host-control-invalid"
		}
		matched := false
		for _, op := range p.Operations {
			if op.OperationID == receipt.OperationID && op.ArtifactDigest == hostaction.Digest(*a) {
				matched = true
			}
		}
		if !matched {
			return "host-control-invalid"
		}
	} else if m.Role != nil {
		return "host-control-invalid"
	}
	if c.ProducerID == "debian-baseline" {
		if p.HostAction == nil || p.HostBaselineScope == nil {
			return "host-control-invalid"
		}
		scope, e := debianbaseline.ScopeForRequest(*p.HostAction)
		if e != nil || hostaction.Digest(scope) != hostaction.Digest(p.HostBaselineScope) || !slices.Contains(scope.ControlIDs, c.ControlID) || scope.SubjectHostID != s.Host.HostID || scope.SubjectIdentityDigest != s.IdentityDigest || scope.ProfileLockDigest != s.ProfileLockDigest || scope.RoleID != c.RoleID {
			return "host-control-invalid"
		}
		if m.Volume == nil && m.ConfigurationDigest != p.HostAction.ActionInputDigest {
			return "host-control-invalid"
		}
	}
	if m.Baseline != nil && (m.Baseline.Verification == "unavailable" || m.Baseline.NativeQualificationDigest != "") {
		return "host-control-failed"
	}
	return ""
}
func (v *hostProofVerifier) controlDigest(req generated.HostControlRequirement) (string, string) {
	digests := []string{}
	if req.Applicability == "volumes" {
		s := v.snapshot
		if len(s.VolumeIDs) == 0 || s.Storage.RecoveryEpoch != s.Revision.RecoveryEpoch {
			return "", "host-prerequisite-missing"
		}
		seen := map[string]bool{}
		for _, volume := range s.VolumeIDs {
			if seen[volume] {
				return "", "host-control-conflict"
			}
			seen[volume] = true
			for _, kind := range []string{"encryption", "recovery"} {
				x, reason := v.measurement("linux.volume-" + kind + ":" + volume)
				if reason != "" {
					return "", reason
				}
				if x.Control.ProducerID != req.ProducerID || x.Measurement.Kind != "volume" || x.Measurement.Volume == nil || x.Measurement.Volume.Binding.VolumeID != volume {
					return "", "host-control-invalid"
				}
				valid := s.Storage.VolumeEvidenceDigests
				if kind == "recovery" {
					valid = s.Storage.RecoveryEvidenceDigests
				}
				if !slices.Contains(valid, x.Measurement.MeasurementDigest) {
					return "", "host-prerequisite-missing"
				}
				at, _ := time.Parse(time.RFC3339, x.Measurement.ObservedAt)
				if v.at.Sub(at) > 10*time.Minute {
					return "", "host-control-stale"
				}
				digests = append(digests, x.Measurement.MeasurementDigest)
			}
		}
	} else {
		for _, id := range req.ProducerControlIDs {
			x, reason := v.measurement(id)
			if reason != "" {
				return "", reason
			}
			if x.Control.ProducerID != req.ProducerID {
				return "", "host-control-invalid"
			}
			digests = append(digests, x.Measurement.MeasurementDigest)
			if id == "linux.role-network-boundary" {
				in, err := linuxrole.DecodeInput([]byte(x.Plan.HostAction.ActionInput))
				if err != nil {
					return "", "host-control-invalid"
				}
				proof, err := RoleNetworkProofDigest(v.snapshot, in, v.at)
				if err != nil {
					return "", "host-probe-missing"
				}
				digests = append(digests, proof)
			}
			if req.ProducerID == "debian-access-native" {
				probes, reason := v.accessProof(x)
				if reason != "" {
					return "", reason
				}
				digests = append(digests, probes...)
			}
		}
	}
	slices.Sort(digests)
	digests = slices.Compact(digests)
	return hostaction.Digest(digests), ""
}
func (v *hostProofVerifier) accessProof(config store.HostAdmissionMeasurement) ([]string, string) {
	confirm, reason := v.measurement("debian-access-confirm")
	if reason != "" {
		return nil, reason
	}
	p := confirm.Plan
	seq := p.HostAccessSequence
	if seq == nil {
		return nil, "host-probe-missing"
	}
	actual, e := debianaccess.Sequence(p.Operations, seq.Actions)
	if e != nil || hostaction.Digest(actual) != hostaction.Digest(*seq) {
		return nil, "host-probe-invalid"
	}
	if seq.SubjectHostID != v.snapshot.Host.HostID || seq.SubjectIdentityDigest != v.snapshot.IdentityDigest || seq.ProfileLockDigest != v.snapshot.ProfileLockDigest {
		return nil, "host-binding-changed"
	}
	if confirm.Receipt.OperationID != seq.ConfirmOperationID || confirm.Measurement.ProducerID != "debian-access-native" {
		return nil, "host-probe-missing"
	}
	var request *generated.HostActionRequest
	if config.Plan.HostAction != nil {
		request = config.Plan.HostAction
	} else if config.Plan.HostAccessSequence != nil && config.Plan.PlanDigest == p.PlanDigest && config.Receipt.RunID == confirm.Receipt.RunID {
		for i, op := range config.Plan.Operations {
			if op.OperationID == config.Receipt.OperationID && i < len(seq.Actions) {
				request = &seq.Actions[i]
			}
		}
	}
	if request == nil || request.ActionID != "debian.access.collect" || request.ActionInputDigest != seq.Actions[0].ActionInputDigest {
		return nil, "host-probe-invalid"
	}
	input, e := debianaccess.DecodeInput([]byte(request.ActionInput))
	if e != nil || hostaction.BytesDigest([]byte(request.ActionInput)) != request.ActionInputDigest || (config.Control.ControlID == "debian.container-firewall" && len(input.ContainerFlows) == 0) {
		return nil, "host-probe-invalid"
	}
	digests := []string{confirm.Measurement.MeasurementDigest}
	for i, action := range seq.Actions {
		if action.ActionID != "debian.access.probe.local" && action.ActionID != "debian.access.probe-source" {
			continue
		}
		var input generated.AccessProbeInput
		if json.Unmarshal([]byte(action.ActionInput), &input) != nil {
			return nil, "host-probe-invalid"
		}
		for _, c := range input.Cases {
			x, reason := v.measurement(c.ProbeID)
			if reason != "" {
				return nil, reason
			}
			o := x.Measurement.Probe
			if o == nil || x.Measurement.ProducerID != "debian-access-probe" || x.Receipt.RunID != confirm.Receipt.RunID || x.Plan.PlanDigest != p.PlanDigest || x.Receipt.OperationID != p.Operations[i].OperationID || o.ProbeID != c.ProbeID || o.SourceHostID != input.Source.HostID || o.SourceIdentityDigest != input.Source.IdentityDigest || o.SourceContextDigest != input.Source.ContextDigest || o.ActualSourceAddress != input.Source.Address || o.Expected != c.Expected || o.Actual != c.Expected || o.DestinationDigest != hostaction.Digest(c.Destination) || o.WitnessDigest == "" || o.SourceNamespaceDigest == "" || x.Measurement.ConfigurationDigest != input.ApplyInputDigest {
				return nil, "host-probe-invalid"
			}
			digests = append(digests, x.Measurement.MeasurementDigest)
		}
	}
	return digests, ""
}

// HostControlProofDigest prepares the inert logical-control check digest from
// the same current observations used by evaluation; it grants no admission.
func HostControlProofDigest(snapshot store.HostAdmissionSnapshot, controlID, stage string, at time.Time) (string, error) {
	req, ok := hostRequirement(snapshot.Profile.RoleID, controlID, stage)
	if !ok {
		return "", errHostAdmission
	}
	v := hostProofVerifier{snapshot: snapshot, at: at}
	digest, reason := v.controlDigest(req)
	if reason != "" {
		return "", errHostAdmission
	}
	return digest, nil
}

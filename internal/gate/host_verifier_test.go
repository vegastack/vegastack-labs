package gate

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/debianaccess"
	"github.com/vegastack/vegastack-labs/internal/debianbaseline"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/store"
	"strings"
	"testing"
	"time"
)

func qualifiedHostSnapshot(t *testing.T, at time.Time) store.HostAdmissionSnapshot {
	t.Helper()
	ops, requests := admissionAccessSequence(t)
	seq, e := debianaccess.Sequence(ops, requests)
	if e != nil {
		t.Fatal(e)
	}
	var input generated.DebianAccessInput
	json.Unmarshal([]byte(requests[0].ActionInput), &input)
	d := hostaction.Digest("synthetic")
	s := store.HostAdmissionSnapshot{Host: generated.ManagedHost{HostID: input.HostID, IdentityClass: "qualified-virtual", Status: "registered"}, Profile: generated.HostProfile{ProfileID: input.ProfileID, OSFamily: "debian", OSVersion: "13.6", Architecture: "amd64", RoleID: "host", DefinitionVersion: "1.0.0"}, ProfileLock: input.ProfileLock, ProfileLockDigest: input.ProfileLockDigest, IdentityDigest: input.HostIdentityDigest, BindingDigest: d, DeclarationID: "current-host-declaration", DeclarationRevision: 1, Revision: store.RevisionToken{StateRevision: 100}, Bundles: map[string]generated.GateEvidenceBundle{}, AppliedBindings: map[string]store.HostAppliedBinding{}, PrerequisiteDigests: map[string]string{}, PrerequisiteEvidenceIDs: map[string]string{}}
	plan := generated.Plan{PlanID: "access-plan", PlanDigest: d, DeclarationID: "access-declaration", Binding: generated.PlanBinding{StateRevision: 10, DeclarationRevision: 1, ToolVersion: "1.0.0"}, HostAccessSequence: &seq, Operations: ops}
	add := func(id, producer, kind string, op int, probe *generated.AccessProbeObservation, config string) {
		m := generated.AccessMeasurement{Schema: generated.SchemaIDAccessMeasurement, SchemaVersion: "1.0.0", ControlID: id, Kind: kind, Status: "passed", SubjectHostID: s.Host.HostID, SubjectIdentityDigest: s.IdentityDigest, ProfileLockDigest: s.ProfileLockDigest, ProducerID: producer, ProducerVersion: "1.0.0", BundleDigest: d, ObservedAt: at.Format(time.RFC3339), ConfigurationDigest: config, PositiveProbeDigest: d, NegativeProbeDigest: d, Reason: "synthetic", Probe: probe}
		if kind == "baseline" {
			m.Baseline = &generated.BaselineObservation{Schema: generated.SchemaIDBaselineObservation, SchemaVersion: "1.0.0", FactsDigest: d, Verification: "configuration-observed"}
		}
		thisPlan := plan
		thisOp := ops[op]
		if producer == "debian-baseline" {
			in := generated.DebianBaselineInput{Schema: generated.SchemaIDDebianBaselineInput, SchemaVersion: "1.0.0", HostID: s.Host.HostID, HostIdentityDigest: s.IdentityDigest, ProfileID: s.Profile.ProfileID, ProfileLock: s.ProfileLock, ProfileLockDigest: s.ProfileLockDigest, RoleID: "host", ActionVersion: "1.0.0", AutomationUID: 1001, ControlIDs: []string{id}, RecoverySourcePrefixes: []string{"192.0.2.1/32"}, UpdateOwner: "operator", TimeOwner: "systemd-timesyncd", AuditPaths: []string{"/etc/passwd"}, AppArmorProfiles: []generated.BaselineApparmorProfile{}, AIDE: generated.BaselineAidePolicy{Schema: generated.SchemaIDBaselineAidePolicy, SchemaVersion: "1.0.0", ScopePaths: []string{}, ScopeDigest: hostaction.Digest([]string{})}, Resources: []generated.BaselineResourceLimit{}, KernelSettings: []generated.BaselineKernelSetting{}, Volumes: []generated.HostVolumeBinding{}}
			in.RenderedPolicyDigest = debianbaseline.PolicyDigest(in)
			raw, _ := json.Marshal(in)
			request := requests[0]
			request.ActionID = "debian.baseline.collect"
			request.ActionInput = string(raw)
			request.ActionInputDigest = hostaction.BytesDigest(raw)
			scope, e := debianbaseline.ScopeForRequest(request)
			if e != nil {
				t.Fatal("baseline fixture", id, e)
			}
			thisOp = ops[1]
			thisOp.OperationID = id
			thisOp.ArtifactDigest = hostaction.Digest(request)
			thisPlan = generated.Plan{PlanID: "plan-" + id, PlanDigest: hostaction.Digest(id), DeclarationID: "decl-" + id, Binding: plan.Binding, HostAction: &request, HostBaselineScope: scope, Operations: []generated.PlanOperation{thisOp}}
			m.ConfigurationDigest = request.ActionInputDigest
		}
		m.MeasurementDigest = hostaction.MeasurementDigest(m)
		r := generated.HostActionResult{Schema: generated.SchemaIDHostActionResult, SchemaVersion: "1.0.0", BundleDigest: d, Status: "succeeded", EffectObserved: true, Reason: "synthetic", ControlMeasurements: []generated.AccessMeasurement{m}}
		r.ResultDigest = hostaction.ResultDigest(r)
		receipt := generated.ExecutionReceipt{Schema: generated.SchemaIDExecutionReceipt, SchemaVersion: "1.0.0", LeaseID: "lease-a", PlanID: thisPlan.PlanID, PlanDigest: thisPlan.PlanDigest, RunID: "run-a", StepID: thisOp.OperationID, OperationID: thisOp.OperationID, ExecutorID: "executor-central", AdapterID: hostaction.AdapterID, TargetID: thisOp.TargetID, ArtifactDigest: thisOp.ArtifactDigest, BindingDigest: d, NonceDigest: d, ReceiptID: "receipt-" + id, Status: "succeeded", ResultDigest: r.ResultDigest, RecordedAt: at.Format(time.RFC3339), Extensions: []generated.ContractExtension{}}
		c := generated.HostControlResult{Schema: generated.SchemaIDHostControlResult, SchemaVersion: "1.0.0", HostID: s.Host.HostID, IdentityDigest: s.IdentityDigest, IdentityClass: s.Host.IdentityClass, ProfileID: s.Profile.ProfileID, OSFamily: "debian", OSVersion: "13.6", Architecture: "amd64", RoleID: "host", BaselineVersion: "1.0.0", ControlID: id, ProducerID: producer, ProducerVersion: "1.0.0", ActionReceiptDigest: hostaction.Digest(receipt), DeclarationID: thisPlan.DeclarationID, DeclarationRevision: 1, ObservedAt: m.ObservedAt, Status: "passed", MeasurementDigest: m.MeasurementDigest, PositiveProbeDigest: d, NegativeProbeDigest: d}
		s.Results = append(s.Results, c)
		s.Measurements = append(s.Measurements, store.HostAdmissionMeasurement{Control: c, Measurement: m, Result: r, Plan: thisPlan, Receipt: receipt})
		s.ActionReceiptDigests = append(s.ActionReceiptDigests, c.ActionReceiptDigest)
	}
	for i, id := range []string{"debian.accounts", "debian.ssh", "debian.host-firewall"} {
		add(id, "debian-access-native", []string{"account", "ssh", "host-flow"}[i], 1, nil, hostaction.Digest(map[string]string{"ssh-config": hostaction.Digest("observed SSH bytes"), "host-rules-v4": hostaction.Digest("observed firewall state")}))
	}
	add("debian-access-confirm", "debian-access-native", "identity", 4, nil, requests[0].ActionInputDigest)
	for i, r := range requests {
		if r.ActionID != "debian.access.probe.local" && r.ActionID != "debian.access.probe-source" {
			continue
		}
		var in generated.AccessProbeInput
		json.Unmarshal([]byte(r.ActionInput), &in)
		for _, c := range in.Cases {
			o := &generated.AccessProbeObservation{Schema: generated.SchemaIDAccessProbeObservation, SchemaVersion: "1.0.0", ProbeID: c.ProbeID, SourceHostID: in.Source.HostID, SourceIdentityDigest: in.Source.IdentityDigest, SourceContextDigest: in.Source.ContextDigest, ActualSourceAddress: in.Source.Address, SourceNamespaceDigest: d, DestinationDigest: hostaction.Digest(c.Destination), WitnessDigest: d, Expected: c.Expected, Actual: c.Expected}
			kind := "ssh"
			if c.Kind == "host-flow" {
				kind = "host-flow"
			}
			if strings.HasPrefix(c.Kind, "container-") {
				kind = "container-flow"
			}
			add(c.ProbeID, "debian-access-probe", kind, i, o, in.ApplyInputDigest)
		}
	}
	for _, id := range []string{"linux.fail2ban-sshd", "linux.audit-bounded", "linux.apparmor-enforcing", "linux.update-health", "linux.time-sync", "linux.resource-health", "linux.kernel-settings"} {
		add(id, "debian-baseline", "baseline", 1, nil, d)
	}
	for _, key := range []string{"identity-console", "recovery-access", "qualified-virtual"} {
		id := "prereq-" + key
		b := hostTestBundle(at)
		b.Checks = []generated.GateEvidenceCheck{hostTestCheck(key, d)}
		b.Facts = []generated.GateEvidenceFact{hostTestFact("host.binding", s.BindingDigest)}
		hostTestEvidence(&s, id, "platform-safety", b, at)
		s.PrerequisiteDigests[key] = d
		s.PrerequisiteEvidenceIDs[key] = id
	}
	q := hostTestBundle(at)
	q.Facts = []generated.GateEvidenceFact{hostTestFact("native.profile-lock", s.ProfileLockDigest), hostTestFact("native.source", d)}
	q.Checks = []generated.GateEvidenceCheck{hostTestCheck("native.baseline", d)}
	hostTestEvidence(&s, "native-baseline", "native.baseline", q, at)
	s.Qualifications = []store.HostNativeQualification{{Stage: "baseline", ProfileDigest: s.ProfileLockDigest, EvidenceID: "native-baseline", SourceDigest: d, ObservedAt: at.Format(time.RFC3339), ExpiresAt: at.Add(time.Hour).Format(time.RFC3339)}}
	s.QualificationDigests = []string{hostaction.Digest(q)}
	platform := hostTestBundle(at)
	platform.Facts = []generated.GateEvidenceFact{hostTestFact("host.binding", s.BindingDigest), hostTestFact("host.profile-lock", s.ProfileLockDigest)}
	hostTestEvidence(&s, "platform-final", "platform-safety", platform, at)
	baseline := platform
	baseline.Checks = []generated.GateEvidenceCheck{}
	controls, e := RequiredHostControls(s.Profile, "baseline")
	if e != nil {
		t.Fatal(e)
	}
	for _, id := range controls {
		digest, e := HostControlProofDigest(s, id, "baseline", at)
		if e != nil {
			t.Fatal("control fixture", id, e)
		}
		baseline.Checks = append(baseline.Checks, hostTestCheck(id, digest))
	}
	hostTestEvidence(&s, "baseline-final", "host.hardening-baseline", baseline, at)
	return s
}
func hostTestBundle(at time.Time) generated.GateEvidenceBundle {
	return generated.GateEvidenceBundle{Schema: generated.SchemaIDGateEvidenceBundle, SchemaVersion: "1.1.0", Facts: []generated.GateEvidenceFact{}, Checks: []generated.GateEvidenceCheck{}, Attachments: []generated.GateEvidenceAttachment{}, CollectorID: "synthetic-test", ObservedAt: at.Format(time.RFC3339)}
}
func hostTestFact(id, d string) generated.GateEvidenceFact {
	return generated.GateEvidenceFact{Schema: generated.SchemaIDGateEvidenceFact, SchemaVersion: "1.1.0", FactID: id, ValueDigest: d}
}
func hostTestCheck(id, d string) generated.GateEvidenceCheck {
	return generated.GateEvidenceCheck{Schema: generated.SchemaIDGateEvidenceCheck, SchemaVersion: "1.1.0", CheckID: id, VerifierVersion: "1.0.0", Result: "passed", ResultDigest: d}
}
func hostTestEvidence(s *store.HostAdmissionSnapshot, id, gate string, b generated.GateEvidenceBundle, at time.Time) {
	e := validAppliedFixture(at)
	e.EvidenceID = id
	e.SubjectID = s.Host.HostID
	e.GateID = gate
	e.BundleDigest = hostaction.Digest(b)
	e.ArtifactDigest = s.BindingDigest
	e.CollectorID = b.CollectorID
	e.ObservedAt = b.ObservedAt
	e.AppliedAt = at.Format(time.RFC3339)
	e.StateRevision = int64(len(s.Evidence) + 1)
	e.DeclarationID = "evidence-" + id
	e.DeclarationRevision = 1
	e.RecoveryEpoch = s.Revision.RecoveryEpoch
	if gate == "host.hardening-baseline" || gate == "host.role-admission" {
		e.DefinitionVersion = "1.1.0"
		e.EvaluatorVersion = "1.1.0"
	}
	s.Evidence = append(s.Evidence, e)
	s.Bundles[id] = b
	s.AppliedBindings[id] = store.HostAppliedBinding{DeclarationID: e.DeclarationID, DeclarationRevision: e.DeclarationRevision, ArtifactDigest: e.ArtifactDigest, BundleDigest: e.BundleDigest, StateRevision: e.StateRevision, ReleaseBuildID: e.ReleaseBuildID, ToolVersion: e.ToolVersion}
}
func TestHostAdmissionEveryControlRequired(t *testing.T) {
	at := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)
	s := qualifiedHostSnapshot(t, at)
	scope := hostScope("vegastack-labs")
	scope.StateRevision = 100
	got, e := EvaluateHostAdmission(context.Background(), s, scope, "host.hardening-baseline", at)
	if e != nil || got.Outcome != "passed" {
		t.Fatal(got, e)
	}
	for i, c := range s.Results {
		copy := s
		copy.Results = append(append([]generated.HostControlResult{}, s.Results[:i]...), s.Results[i+1:]...)
		got, e := EvaluateHostAdmission(context.Background(), copy, scope, "host.hardening-baseline", at)
		if e == nil && got.Outcome == "passed" {
			t.Fatal("missing result admitted", c.ControlID)
		}
	}
}

package qualification

import (
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/debianbaseline"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"testing"
	"time"
)

func volumeProducerInput(t *testing.T, e ProducerExecution, action string, input any, binding generated.HostVolumeBinding, kind string) ProducerExecution {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	r := *e.Plan.HostAction
	r.ActionID, r.ActionInput, r.ActionInputDigest = action, string(raw), hostaction.BytesDigest(raw)
	if kind == "mapping" {
		r.HostID = binding.HostID
	}
	e.Plan.HostAction = &r
	e.Plan.Operations = append([]generated.PlanOperation(nil), e.Plan.Operations...)
	e.Plan.Operations[0].ArtifactDigest = hostaction.Digest(r)
	e.Receipt.ArtifactDigest, e.Receipt.TargetID = hostaction.Digest(r), r.HostID
	e.Reference.HostID = r.HostID
	result := *e.Result
	result.ControlMeasurements = append([]generated.AccessMeasurement(nil), result.ControlMeasurements...)
	m := &result.ControlMeasurements[0]
	volume := *m.Volume
	volume.Binding, volume.Kind = binding, kind
	if kind == "mapping" {
		volume.PriorVolumeReceiptDigest = ""
		m.ControlID = "linux.volume-encryption:" + binding.VolumeID
	}
	if recovery, ok := input.(generated.VolumeRecoveryInput); ok {
		volume.PriorVolumeReceiptDigest = recovery.PriorVolumeReceiptDigest
	}
	m.Volume = &volume
	m.ConfigurationDigest = hostaction.Digest(binding)
	m.MeasurementDigest = hostaction.MeasurementDigest(*m)
	result.ResultDigest = hostaction.ResultDigest(result)
	e.Result = &result
	e.Receipt.ResultDigest = result.ResultDigest
	return e
}

func TestNativeVolumeMappingRequiresOwningObserveAction(t *testing.T) {
	e, o := volumeEvidenceFixture(t)
	r := *o.VolumeCase.RecoveryInput
	d := r.ProfileLockDigest
	in := generated.DebianBaselineInput{Schema: generated.SchemaIDDebianBaselineInput, SchemaVersion: "1.0.0", HostID: r.Binding.HostID, HostIdentityDigest: r.Binding.HostIdentityDigest,
		ProfileID: r.ProfileID, ProfileLockDigest: d, ProfileLock: r.ProfileLock, RoleID: "host", ActionVersion: "1.0.0", AutomationUID: r.AutomationUID,
		RenderedPolicyDigest: d, ControlIDs: []string{"linux.volume-encryption:data"}, RecoverySourcePrefixes: []string{}, UpdateOwner: "operator", TimeOwner: "systemd-timesyncd", AuditPaths: []string{},
		AppArmorProfiles: []generated.BaselineApparmorProfile{}, AIDE: generated.BaselineAidePolicy{Schema: generated.SchemaIDBaselineAidePolicy, SchemaVersion: "1.0.0", ScopePaths: []string{}, ScopeDigest: d},
		Resources: []generated.BaselineResourceLimit{}, KernelSettings: []generated.BaselineKernelSetting{}, Volumes: []generated.HostVolumeBinding{r.Binding}}
	w := *o.VolumeCase
	w.ScenarioID, w.InputDigest, w.ObservedOutcome = "volume-effective-mapping", hostaction.Digest(in), "accepted"
	w.BaselineInput, w.RecoveryInput = &in, nil
	o.VolumeCase = &w
	for _, action := range []string{"debian.volume.observe", "debian.baseline.collect"} {
		x := volumeProducerInput(t, e, action, in, r.Binding, "mapping")
		err := validateVolumeCaseExecutions(w.ScenarioID, []ProducerExecution{x}, []generated.NativeObservation{o})
		if (err == nil) != (action == "debian.volume.observe") {
			t.Fatalf("owning mapping action %s: %v", action, err)
		}
	}
}

func TestNativeRevokedVolumeRequiresRealRevisionAndReceiptLineage(t *testing.T) {
	e, o := volumeEvidenceFixture(t)
	prior := *o.VolumeCase.RecoveryInput
	current := prior
	current.Binding.DeclarationRevision++
	current.Binding.RecoveryReferenceDigest = hostaction.Digest("current-policy")
	current.RecoveryMaterialVersion = "v2"
	current.PriorVolumeReceiptDigest = hostaction.Digest("current-mapping-receipt")
	if !debianbaseline.VolumeRecoveryRotationMatches(current, prior) {
		t.Fatal("test fixture rotation mismatch")
	}
	w := *o.VolumeCase
	w.ScenarioID, w.InputDigest, w.BindingDigest = "volume-revoked-binding", hostaction.Digest(current), hostaction.Digest(current.Binding)
	w.OriginalPolicyDigest, w.OriginalPolicyAfterDigest = current.Binding.RecoveryReferenceDigest, current.Binding.RecoveryReferenceDigest
	w.RecoveryInput, w.PriorRecoveryInput = &current, &prior
	o.VolumeCase = &w
	old := volumeProducerInput(t, e, "debian.volume-recovery.verify", prior, prior.Binding, "recovery")
	now := volumeProducerInput(t, e, "debian.volume-recovery.verify", current, current.Binding, "recovery")
	if err := validateVolumeCaseExecutions(w.ScenarioID, []ProducerExecution{old, now}, []generated.NativeObservation{o, o}); err != nil {
		t.Fatal(err)
	}
	if err := validateVolumeCaseExecutions(w.ScenarioID, []ProducerExecution{now, now}, []generated.NativeObservation{o, o}); err == nil {
		t.Fatal("invented prior producer accepted")
	}
}

func volumeEvidenceFixture(t *testing.T) (ProducerExecution, generated.NativeObservation) {
	t.Helper()
	d := hostaction.Digest("synthetic-volume-predicate")
	now := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	b := generated.HostVolumeBinding{Schema: generated.SchemaIDHostVolumeBinding, SchemaVersion: "1.0.0", HostID: "subject", HostIdentityDigest: d, VolumeID: "data", ControlHostID: "controller", ControlHostIdentityDigest: hostaction.Digest("controller"), HeaderBytes: 16 << 20, LUKSUUID: "11111111-2222-3333-4444-555555555555", HeaderDigest: d, MappingDigest: d, MountBindingDigest: d, MapperName: "data", MountPath: "/srv/data", DeviceMajor: 8, DeviceMinor: 1, KeySlot: 0, RecoveryCustodianID: "custodian", RecoveryCustodianIdentityDigest: hostaction.Digest("custodian"), RecoveryTargetDigest: d, RecoveryReferenceDigest: d, DeclarationID: "declaration", DeclarationRevision: 1}
	in := generated.VolumeRecoveryInput{Schema: generated.SchemaIDVolumeRecoveryInput, SchemaVersion: "1.0.0", HostID: b.RecoveryCustodianID, HostIdentityDigest: b.RecoveryCustodianIdentityDigest, ProfileID: "debian-13-amd64", ProfileLockDigest: d, Binding: b, PriorVolumeReceiptDigest: d, RecoveryReferenceID: "recovery-data", RecoveryMaterialVersion: "v1"}
	roles := reserveRoleEvidence(t)
	var role generated.LinuxRoleInput
	if err := json.Unmarshal([]byte(roles[0].Plan.HostAction.ActionInput), &role); err != nil {
		t.Fatal(err)
	}
	in.RoleID = "host"
	in.ActionVersion = "1.0.0"
	in.AutomationUID = 1001
	in.ProfileLock = role.ProfileLock
	in.ProfileLockDigest = hostaction.Digest(role.ProfileLock)
	raw, _ := json.Marshal(in)
	r := generated.HostActionRequest{HostID: in.HostID, ActionID: "debian.volume-recovery.verify", ActionInput: string(raw), ActionInputDigest: hostaction.BytesDigest(raw)}
	m := generated.AccessMeasurement{Schema: generated.SchemaIDAccessMeasurement, SchemaVersion: "1.0.0", ControlID: "linux.volume-recovery:data", Kind: "volume", Status: "passed", SubjectHostID: b.HostID, SubjectIdentityDigest: b.HostIdentityDigest, ProfileLockDigest: d, ProducerID: "debian-baseline", ProducerVersion: "1.0.0", BundleDigest: d, ObservedAt: now, ConfigurationDigest: hostaction.Digest(b), PositiveProbeDigest: d, NegativeProbeDigest: d, Reason: "observed-native-volume", Volume: &generated.VolumeObservation{Schema: generated.SchemaIDVolumeObservation, SchemaVersion: "1.0.0", Binding: b, Kind: "recovery", FactsDigest: d, PriorVolumeReceiptDigest: d, ObservedAt: now}}
	m.MeasurementDigest = hostaction.MeasurementDigest(m)
	result := generated.HostActionResult{Schema: generated.SchemaIDHostActionResult, SchemaVersion: "1.0.0", BundleDigest: d, Status: "succeeded", EffectObserved: true, Reason: "verified", ControlMeasurements: []generated.AccessMeasurement{m}}
	result.ResultDigest = hostaction.ResultDigest(result)
	if err := hostaction.ValidateResult(result); err != nil {
		t.Fatal(err)
	}
	e := ProducerExecution{Reference: generated.NativeProducerReference{HostID: in.HostID}, Plan: generated.Plan{HostAction: &r, Operations: []generated.PlanOperation{{OperationID: "op", AdapterID: hostaction.AdapterID, ArtifactDigest: hostaction.Digest(r)}}}, Receipt: generated.ExecutionReceipt{OperationID: "op", TargetID: in.HostID, ArtifactDigest: hostaction.Digest(r), Status: "succeeded", ResultDigest: result.ResultDigest}, Result: &result}
	w := generated.NativeVolumeCaseWitness{Schema: generated.SchemaIDNativeVolumeCaseWitness, SchemaVersion: "1.0.0", ScenarioID: "volume-wrong-key", InputDigest: hostaction.Digest(in), BindingDigest: hostaction.Digest(b), HeaderBeforeDigest: d, HeaderAfterDigest: d, OriginalPolicyDigest: d, OriginalPolicyAfterDigest: d, TestedCopyBeforeDigest: d, TestedCopyAfterDigest: d, TestedKeySlot: 0, ObservedOutcome: "refused", ObservedAt: now, RecoveryInput: &in}
	return e, generated.NativeObservation{ObservedAt: now, VolumeCase: &w}
}
func TestVolumeNegativeRequiresBoundActualProducerAndUnchangedOriginal(t *testing.T) {
	e, o := volumeEvidenceFixture(t)
	if !exactNativeJSON(generated.SchemaIDNativeVolumeCaseWitness, *o.VolumeCase) {
		raw, _ := json.Marshal(*o.VolumeCase)
		t.Fatal(generated.ValidateContractJSON(generated.SchemaIDNativeVolumeCaseWitness, raw, generated.ContractExact))
	}
	if _, err := producerAction(e); err != nil {
		t.Fatalf("fixture producer: %v", err)
	}
	if err := validateVolumeCaseExecutions("volume-wrong-key", []ProducerExecution{e}, []generated.NativeObservation{o}); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"original-write", "copy-write", "policy-change", "accepted-key", "other-input", "other-binding", "future-witness", "missing-measurement", "fake-prior"} {
		t.Run(kind, func(t *testing.T) {
			e, o := volumeEvidenceFixture(t)
			switch kind {
			case "original-write":
				o.VolumeCase.HeaderAfterDigest = hostaction.Digest("changed")
			case "copy-write":
				o.VolumeCase.TestedCopyAfterDigest = hostaction.Digest("changed")
			case "policy-change":
				o.VolumeCase.OriginalPolicyAfterDigest = hostaction.Digest("changed")
			case "accepted-key":
				o.VolumeCase.ObservedOutcome = "accepted"
			case "other-input":
				o.VolumeCase.InputDigest = hostaction.Digest("other")
			case "other-binding":
				o.VolumeCase.BindingDigest = hostaction.Digest("other")
			case "future-witness":
				o.VolumeCase.ObservedAt = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
			case "missing-measurement":
				e.Result.ControlMeasurements = nil
				e.Result.ResultDigest = hostaction.ResultDigest(*e.Result)
				e.Receipt.ResultDigest = e.Result.ResultDigest
			case "fake-prior":
				o.VolumeCase.PriorRecoveryInput = o.VolumeCase.RecoveryInput
			}
			if validateVolumeCaseExecutions("volume-wrong-key", []ProducerExecution{e}, []generated.NativeObservation{o}) == nil {
				t.Fatal("unbound negative qualified")
			}
		})
	}
}

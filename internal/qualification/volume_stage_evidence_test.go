package qualification

import (
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"testing"
	"time"
)

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

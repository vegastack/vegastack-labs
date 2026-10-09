package gate

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/debianbaseline"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/store"
	"testing"
	"time"
)

func resealHostMeasurement(s *store.HostAdmissionSnapshot, x *store.HostAdmissionMeasurement) {
	x.Measurement.MeasurementDigest = hostaction.MeasurementDigest(x.Measurement)
	x.Result.ControlMeasurements = []generated.AccessMeasurement{x.Measurement}
	x.Result.ResultDigest = hostaction.ResultDigest(x.Result)
	x.Receipt.ResultDigest = x.Result.ResultDigest
	x.Control.MeasurementDigest = x.Measurement.MeasurementDigest
	x.Control.ActionReceiptDigest = hostaction.Digest(x.Receipt)
	s.ActionReceiptDigests = append(s.ActionReceiptDigests, x.Control.ActionReceiptDigest)
}
func qualifiedRoleSnapshot(t *testing.T, at time.Time) store.HostAdmissionSnapshot {
	t.Helper()
	s := qualifiedHostSnapshot(t, at)
	s.Profile.RoleID = "control"
	s.RoleBindingDigest = hostaction.Digest("current control declaration")
	s.BindingDigest = hostaction.Digest("current control host binding")
	var template store.HostAdmissionMeasurement
	for i := range s.Measurements {
		x := &s.Measurements[i]
		if x.Control.ProducerID != "debian-baseline" {
			continue
		}
		var in generated.DebianBaselineInput
		json.Unmarshal([]byte(x.Plan.HostAction.ActionInput), &in)
		in.RoleID = "control"
		in.RenderedPolicyDigest = debianbaseline.PolicyDigest(in)
		raw, _ := json.Marshal(in)
		x.Plan.HostAction.ActionInput = string(raw)
		x.Plan.HostAction.ActionInputDigest = hostaction.BytesDigest(raw)
		scope, e := debianbaseline.ScopeForRequest(*x.Plan.HostAction)
		if e != nil {
			t.Fatal(e)
		}
		x.Plan.HostBaselineScope = scope
		x.Plan.Operations[0].ArtifactDigest = hostaction.Digest(*x.Plan.HostAction)
		x.Receipt.ArtifactDigest = x.Plan.Operations[0].ArtifactDigest
		x.Control.RoleID = "control"
		x.Measurement.ConfigurationDigest = x.Plan.HostAction.ActionInputDigest
		resealHostMeasurement(&s, x)
		s.Results[i] = x.Control
		template = *x
	}
	add := func(id string, change func(*store.HostAdmissionMeasurement)) store.HostAdmissionMeasurement {
		raw, _ := json.Marshal(template)
		var x store.HostAdmissionMeasurement
		json.Unmarshal(raw, &x)
		x.Control.ControlID = id
		x.Measurement.ControlID = id
		x.Plan.PlanID = "role-plan-" + id
		x.Plan.PlanDigest = hostaction.Digest(id)
		x.Plan.DeclarationID = "role-decl-" + id
		x.Control.DeclarationID = x.Plan.DeclarationID
		x.Plan.Operations[0].OperationID = id
		x.Receipt.OperationID = id
		x.Receipt.StepID = id
		x.Receipt.PlanID = x.Plan.PlanID
		x.Receipt.PlanDigest = x.Plan.PlanDigest
		x.Receipt.ReceiptID = "role-receipt-" + id
		change(&x)
		x.Plan.Operations[0].ArtifactDigest = hostaction.Digest(*x.Plan.HostAction)
		x.Receipt.ArtifactDigest = x.Plan.Operations[0].ArtifactDigest
		resealHostMeasurement(&s, &x)
		s.Results = append(s.Results, x.Control)
		s.Measurements = append(s.Measurements, x)
		return x
	}
	baselineInput := func(x *store.HostAdmissionMeasurement, in generated.DebianBaselineInput, action string) {
		in.ControlIDs = []string{x.Control.ControlID}
		in.RenderedPolicyDigest = debianbaseline.PolicyDigest(in)
		raw, _ := json.Marshal(in)
		x.Plan.HostAction.ActionID = action
		x.Plan.HostAction.ActionInput = string(raw)
		x.Plan.HostAction.ActionInputDigest = hostaction.BytesDigest(raw)
		scope, e := debianbaseline.ScopeForRequest(*x.Plan.HostAction)
		if e != nil {
			t.Fatal(x.Control.ControlID, e)
		}
		x.Plan.HostBaselineScope = scope
		x.Measurement.ConfigurationDigest = x.Plan.HostAction.ActionInputDigest
	}
	var base generated.DebianBaselineInput
	json.Unmarshal([]byte(template.Plan.HostAction.ActionInput), &base)
	add("linux.aide-integrity", func(x *store.HostAdmissionMeasurement) {
		in := base
		in.AIDE.ScopePaths = []string{"/etc/passwd"}
		in.AIDE.ScopeDigest = hostaction.Digest(in.AIDE.ScopePaths)
		in.AIDE.ReferenceDigest = hostaction.Digest("actual reference")
		baselineInput(x, in, "debian.baseline.collect")
		x.Measurement.Baseline.AIDEReferenceDigest = in.AIDE.ReferenceDigest
	})
	d := hostaction.Digest
	b := generated.HostVolumeBinding{Schema: generated.SchemaIDHostVolumeBinding, SchemaVersion: "1.0.0", HostID: s.Host.HostID, HostIdentityDigest: s.IdentityDigest, VolumeID: "data", ControlHostID: "controller", ControlHostIdentityDigest: d("controller"), HeaderBytes: 16 << 20, LUKSUUID: "11111111-2222-3333-4444-555555555555", HeaderDigest: d("header"), MappingDigest: d("mapping"), MountBindingDigest: d("mount"), MapperName: "data", MountPath: "/srv/data", DeviceMajor: 8, DeviceMinor: 1, KeySlot: 0, RecoveryCustodianID: "custodian", RecoveryCustodianIdentityDigest: d("custodian"), RecoveryTargetDigest: d("target"), RecoveryReferenceDigest: d("reference"), DeclarationID: "volume-declaration", DeclarationRevision: 1}
	volume := add("linux.volume-encryption:data", func(x *store.HostAdmissionMeasurement) {
		in := base
		in.Volumes = []generated.HostVolumeBinding{b}
		baselineInput(x, in, "debian.volume.observe")
		x.Measurement.Baseline = nil
		x.Measurement.Kind = "volume"
		x.Measurement.ConfigurationDigest = d(b)
		x.Measurement.Volume = &generated.VolumeObservation{Schema: generated.SchemaIDVolumeObservation, SchemaVersion: "1.0.0", Binding: b, Kind: "mapping", FactsDigest: d("actual mapping"), ObservedAt: at.Format(time.RFC3339)}
	})
	recovery := add("linux.volume-recovery:data", func(x *store.HostAdmissionMeasurement) {
		in := generated.VolumeRecoveryInput{Schema: generated.SchemaIDVolumeRecoveryInput, SchemaVersion: "1.0.0", HostID: b.RecoveryCustodianID, HostIdentityDigest: b.RecoveryCustodianIdentityDigest, ProfileID: s.Profile.ProfileID, ProfileLock: s.ProfileLock, ProfileLockDigest: s.ProfileLockDigest, RoleID: "control", ActionVersion: "1.0.0", AutomationUID: 1001, Binding: b, PriorVolumeReceiptDigest: volume.Control.ActionReceiptDigest, RecoveryReferenceID: "recovery-data", RecoveryMaterialVersion: "v1"}
		raw, _ := json.Marshal(in)
		x.Plan.HostAction.ActionID = "debian.volume-recovery.verify"
		x.Plan.HostAction.HostID = b.RecoveryCustodianID
		x.Plan.HostAction.ConsoleConfirmation.HostIdentityDigest = b.RecoveryCustodianIdentityDigest
		x.Plan.HostAction.ActionInput = string(raw)
		x.Plan.HostAction.ActionInputDigest = hostaction.BytesDigest(raw)
		scope, e := debianbaseline.ScopeForRequest(*x.Plan.HostAction)
		if e != nil {
			t.Fatal(e)
		}
		x.Plan.HostBaselineScope = scope
		x.Measurement.Baseline = nil
		x.Measurement.Kind = "volume"
		x.Measurement.ConfigurationDigest = d(b)
		x.Measurement.Volume = &generated.VolumeObservation{Schema: generated.SchemaIDVolumeObservation, SchemaVersion: "1.0.0", Binding: b, Kind: "recovery", FactsDigest: d("actual recovery"), ObservedAt: at.Format(time.RFC3339), PriorVolumeReceiptDigest: volume.Control.ActionReceiptDigest}
	})
	s.VolumeIDs = []string{"data"}
	s.Storage.VolumeEvidenceDigests = []string{volume.Measurement.MeasurementDigest}
	s.Storage.RecoveryEvidenceDigests = []string{recovery.Measurement.MeasurementDigest}
	for _, id := range []string{"linux.role-identity-paths", "linux.role-service-resources", "linux.role-network-boundary", "linux.control-service"} {
		add(id, func(x *store.HostAdmissionMeasurement) {
			x.Control.ProducerID = "linux-role"
			x.Measurement.ProducerID = "linux-role"
			x.Measurement.Kind = "role"
			x.Measurement.Baseline = nil
			x.Measurement.Role = &generated.RoleObservation{Schema: generated.SchemaIDRoleObservation, SchemaVersion: "1.0.0", RoleID: "control", RoleBindingDigest: s.RoleBindingDigest, FactsDigest: d(id), Verification: "effective-probe"}
			x.Plan.HostBaselineScope = nil
			x.Plan.HostAction.ActionID = "debian.role.collect"
			x.Plan.HostAction.ActionInput = `{"fixture":"exact-role-intent"}`
			x.Plan.HostAction.ActionInputDigest = hostaction.BytesDigest([]byte(x.Plan.HostAction.ActionInput))
			x.Measurement.ConfigurationDigest = x.Plan.HostAction.ActionInputDigest
		})
	}
	// Container measurement remains bound to the exact validated access sequence, including all four container cases.
	for _, original := range s.Measurements {
		if original.Control.ControlID == "debian.host-firewall" {
			x := original
			x.Control.ControlID = "debian.container-firewall"
			x.Measurement.ControlID = x.Control.ControlID
			x.Measurement.Kind = "container-flow"
			resealHostMeasurement(&s, &x)
			s.Results = append(s.Results, x.Control)
			s.Measurements = append(s.Measurements, x)
			break
		}
	}
	for i := range s.Evidence {
		e := &s.Evidence[i]
		bundle := s.Bundles[e.EvidenceID]
		for j := range bundle.Facts {
			if bundle.Facts[j].FactID == "host.binding" {
				bundle.Facts[j].ValueDigest = s.BindingDigest
			}
		}
		s.Bundles[e.EvidenceID] = bundle
		e.BundleDigest = d(bundle)
		binding := s.AppliedBindings[e.EvidenceID]
		binding.BundleDigest = e.BundleDigest
		s.AppliedBindings[e.EvidenceID] = binding
	}
	q := hostTestBundle(at)
	q.Facts = []generated.GateEvidenceFact{hostTestFact("native.profile-lock", s.ProfileLockDigest), hostTestFact("native.source", d("role source"))}
	q.Checks = []generated.GateEvidenceCheck{hostTestCheck("native.role", d("role source"))}
	hostTestEvidence(&s, "native-role", "native.role", q, at)
	s.Qualifications = append(s.Qualifications, store.HostNativeQualification{Stage: "role", ProfileDigest: s.ProfileLockDigest, EvidenceID: "native-role", SourceDigest: d("role source"), ObservedAt: at.Format(time.RFC3339), ExpiresAt: at.Add(time.Hour).Format(time.RFC3339)})
	s.QualificationDigests = append(s.QualificationDigests, d(q))
	for _, stage := range []string{"baseline", "role"} {
		bundle := hostTestBundle(at)
		bundle.Facts = []generated.GateEvidenceFact{hostTestFact("host.binding", s.BindingDigest), hostTestFact("host.profile-lock", s.ProfileLockDigest), hostTestFact("host.role-binding", s.RoleBindingDigest)}
		ids, e := RequiredHostControls(s.Profile, stage)
		if e != nil {
			t.Fatal(e)
		}
		for _, id := range ids {
			digest, e := HostControlProofDigest(s, id, stage, at)
			if e != nil {
				t.Fatal(stage, id, e)
			}
			bundle.Checks = append(bundle.Checks, hostTestCheck(id, digest))
		}
		gate := "host.hardening-baseline"
		if stage == "role" {
			gate = "host.role-admission"
		}
		hostTestEvidence(&s, "control-"+stage, gate, bundle, at)
	}
	return s
}
func TestHostRoleAdmissionPositiveAndRequiredRows(t *testing.T) {
	at := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)
	s := qualifiedRoleSnapshot(t, at)
	scope := hostScope("vegastack-labs")
	scope.StateRevision = 100
	got, e := EvaluateHostAdmission(context.Background(), s, scope, "host.role-admission", at)
	if e != nil || got.Outcome != "passed" {
		t.Fatal(got, e)
	}
	for _, id := range []string{"debian.container-firewall", "linux.aide-integrity", "linux.volume-encryption:data", "linux.volume-recovery:data", "linux.role-identity-paths", "linux.role-service-resources", "linux.role-network-boundary", "linux.control-service"} {
		t.Run(id, func(t *testing.T) {
			copy := cloneHostSnapshot(t, s)
			for i, c := range copy.Results {
				if c.ControlID == id {
					copy.Results = append(copy.Results[:i], copy.Results[i+1:]...)
					break
				}
			}
			got, e := EvaluateHostAdmission(context.Background(), copy, scope, "host.role-admission", at)
			if e != nil || got.Outcome == "passed" {
				t.Fatal(got, e)
			}
		})
	}
}

func TestHostRoleRejectsSpoofedProjectionAndKeepsBaselineIndependent(t *testing.T) {
	at := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)
	full := qualifiedRoleSnapshot(t, at)
	scope := hostScope("vegastack-labs")
	scope.StateRevision = 100
	for _, kind := range []string{"wrong-kind", "unrelated-action", "missing-role-binding", "role-storage-blocker"} {
		t.Run(kind, func(t *testing.T) {
			s := cloneHostSnapshot(t, full)
			switch kind {
			case "missing-role-binding":
				s.RoleBindingDigest = ""
			case "role-storage-blocker":
				s.RoleBlockers = []string{"host-prerequisite-missing"}
			default:
				for i := range s.Measurements {
					x := &s.Measurements[i]
					if x.Control.ControlID != "linux.control-service" {
						continue
					}
					if kind == "wrong-kind" {
						x.Measurement.Kind = "identity"
					} else {
						x.Plan.HostAction.ActionID = "debian.baseline.collect"
						x.Plan.Operations[0].ArtifactDigest = hostaction.Digest(*x.Plan.HostAction)
						x.Receipt.ArtifactDigest = x.Plan.Operations[0].ArtifactDigest
					}
					resealHostMeasurement(&s, x)
					s.Results[i] = x.Control
				}
			}
			got, e := EvaluateHostAdmission(context.Background(), s, scope, "host.role-admission", at)
			if e != nil || got.Outcome == "passed" {
				t.Fatal(got, e)
			}
			if kind == "role-storage-blocker" {
				got, e = EvaluateHostAdmission(context.Background(), s, scope, "host.hardening-baseline", at)
				if e != nil || got.Outcome != "passed" {
					t.Fatal("role-only prerequisite blocked preparation", got, e)
				}
			}
		})
	}
}

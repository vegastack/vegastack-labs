//go:build linux

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/debianbaseline"
	"github.com/vegastack/vegastack-labs/internal/gate"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostreplacement"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/linuxrole"
	planengine "github.com/vegastack/vegastack-labs/internal/plan"
	"github.com/vegastack/vegastack-labs/internal/result"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/store"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// This finite synthetic observation/provenance fixture mirrors the gate's
// qualified role facts. Admission still resolves actual canonical SQLite joins
// and runs the common evaluator; no replacement state or gate result is mocked.
func resealHostMeasurement(s *store.HostAdmissionSnapshot, x *store.HostAdmissionMeasurement) {
	x.Measurement.MeasurementDigest = hostaction.MeasurementDigest(x.Measurement)
	x.Result.ControlMeasurements = []generated.AccessMeasurement{x.Measurement}
	x.Result.ResultDigest = hostaction.ResultDigest(x.Result)
	x.Receipt.ResultDigest = x.Result.ResultDigest
	x.Control.MeasurementDigest = x.Measurement.MeasurementDigest
	x.Control.ActionReceiptDigest = hostaction.Digest(x.Receipt)
	s.ActionReceiptDigests = append(s.ActionReceiptDigests, x.Control.ActionReceiptDigest)
}
func replacementApplicationRole(in *generated.LinuxRoleInput) {
	in.RoleID = "application"
	in.Accounts[0].Selector = "application"
	in.Accounts[0].UID = 2001
	in.Accounts[0].GID = 2001
	in.Accounts[0].Existing = false
	for i := range in.Directories {
		in.Directories[i].UID = 2001
		in.Directories[i].GID = 2001
	}
	work := in.Directories[0]
	work.Selector = "work"
	in.Directories = append(in.Directories, work)
}

func replacementQualifiedRoleSnapshot(t *testing.T, at time.Time, stateless ...bool) store.HostAdmissionSnapshot {
	t.Helper()
	roleID := "control"
	if len(stateless) > 0 && stateless[0] {
		roleID = "application"
	}
	return replacementQualifiedRoleSnapshotForInput(t, at, admissionAccessInput(t, "aide", "cryptsetup-bin"), roleID)
}

func replacementQualifiedRoleSnapshotForInput(t *testing.T, at time.Time, access generated.DebianAccessInput, roleID string, target ...generated.HostDiscoveryTargetDraftRequest) store.HostAdmissionSnapshot {
	ops, requests := admissionAccessSequenceForInput(t, access, true, target...)
	s := qualifiedHostSnapshotFromSequence(t, at, ops, requests)
	var roleInput generated.LinuxRoleInput
	if err := json.Unmarshal(roleTestInputJSON, &roleInput); err != nil {
		t.Fatal("role fixture", err)
	}
	for _, m := range s.Measurements {
		if m.Control.ControlID == "debian.host-firewall" {
			var access generated.DebianAccessInput
			var raw string
			if m.Plan.HostAction != nil {
				raw = m.Plan.HostAction.ActionInput
			} else if m.Plan.HostAccessSequence != nil {
				raw = m.Plan.HostAccessSequence.Actions[0].ActionInput
			}
			if json.Unmarshal([]byte(raw), &access) != nil {
				t.Fatal("network input")
			}
			roleInput.NetworkAccess = &access
		}
	}
	roleInput.HostID = s.Host.HostID
	roleInput.HostIdentityDigest = s.IdentityDigest
	roleInput.ProfileID = s.Profile.ProfileID
	roleInput.ProfileLock = s.ProfileLock
	roleInput.ProfileLockDigest = s.ProfileLockDigest
	roleInput.AutomationUID = roleInput.NetworkAccess.AutomationUID
	roleInput.Accounts[0].UID = roleInput.AutomationUID
	for i := range roleInput.Directories {
		roleInput.Directories[i].UID = roleInput.AutomationUID
	}
	if roleID == "application" {
		replacementApplicationRole(&roleInput)
	}
	roleInput.RenderedPolicyDigest = linuxrole.PolicyDigest(roleInput)
	roleInput.RoleBindingDigest = linuxrole.RoleBindingDigest(roleInput)
	if err := linuxrole.ValidateInput(roleInput); err != nil {
		t.Fatal("role fixture invalid", err)
	}
	s.RoleIntentRevision = 1
	s.Profile.RoleID = roleID
	s.RoleBindingDigest = roleInput.RoleBindingDigest
	s.BindingDigest = hostaction.Digest("current control host binding")
	var template store.HostAdmissionMeasurement
	for i := range s.Measurements {
		x := &s.Measurements[i]
		if x.Control.ProducerID != "debian-baseline" {
			continue
		}
		var in generated.DebianBaselineInput
		json.Unmarshal([]byte(x.Plan.HostAction.ActionInput), &in)
		in.RoleID = roleID
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
		x.Control.RoleID = roleID
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
	if roleID == "control" {
		add("linux.aide-integrity", func(x *store.HostAdmissionMeasurement) {
			in := base
			in.AIDE.ScopePaths = []string{"/etc/passwd"}
			in.AIDE.ScopeDigest = hostaction.Digest(in.AIDE.ScopePaths)
			in.AIDE.ReferenceDigest = hostaction.Digest("actual reference")
			baselineInput(x, in, "debian.baseline.collect")
			x.Measurement.Baseline.AIDEReferenceDigest = in.AIDE.ReferenceDigest
		})
	}
	d := hostaction.Digest
	{
		b := generated.HostVolumeBinding{Schema: generated.SchemaIDHostVolumeBinding, SchemaVersion: "1.0.0", HostID: s.Host.HostID, HostIdentityDigest: s.IdentityDigest, VolumeID: "data", ControlHostID: "controller", ControlHostIdentityDigest: d("controller"), HeaderBytes: 16 << 20, LUKSUUID: "11111111-2222-3333-4444-555555555555", HeaderDigest: d("header"), MappingDigest: d("mapping"), MountBindingDigest: d("mount"), MapperName: "data", MountPath: "/srv/data", DeviceMajor: 8, DeviceMinor: 1, KeySlot: 0, RecoveryCustodianID: "custodian", RecoveryCustodianIdentityDigest: d("custodian"), RecoveryTargetDigest: d("target"), RecoveryReferenceDigest: d("reference"), DeclarationID: "volume-declaration", DeclarationRevision: 1}
		if access.HostID != "test-host" {
			b.DeclarationID = access.HostID + "-volume"
			b.ControlHostID = access.HostID + "-controller"
			b.ControlHostIdentityDigest = d(b.ControlHostID)
			b.RecoveryCustodianID = access.HostID + "-custodian"
			b.RecoveryCustodianIdentityDigest = d(b.RecoveryCustodianID)
		}
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
			in := generated.VolumeRecoveryInput{Schema: generated.SchemaIDVolumeRecoveryInput, SchemaVersion: "1.0.0", HostID: b.RecoveryCustodianID, HostIdentityDigest: b.RecoveryCustodianIdentityDigest, ProfileID: s.Profile.ProfileID, ProfileLock: s.ProfileLock, ProfileLockDigest: s.ProfileLockDigest, RoleID: roleID, ActionVersion: "1.0.0", AutomationUID: 1001, Binding: b, PriorVolumeReceiptDigest: volume.Control.ActionReceiptDigest, RecoveryReferenceID: "recovery-data", RecoveryMaterialVersion: "v1"}
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
	}
	roleControls := []string{"linux.role-identity-paths", "linux.role-service-resources", "linux.role-network-boundary"}
	if roleID == "control" {
		roleControls = append(roleControls, "linux.control-service")
	} else {
		roleControls = append(roleControls, "linux.role-workload-isolation")
	}
	for _, id := range roleControls {
		add(id, func(x *store.HostAdmissionMeasurement) {
			x.Control.ProducerID = "linux-role"
			x.Measurement.ProducerID = "linux-role"
			x.Measurement.Kind = "role"
			x.Measurement.Baseline = nil
			x.Measurement.Role = &generated.RoleObservation{Schema: generated.SchemaIDRoleObservation, SchemaVersion: "1.0.0", RoleID: roleID, RoleBindingDigest: s.RoleBindingDigest, FactsDigest: d(id), Verification: "effective-probe"}
			x.Plan.HostBaselineScope = nil
			x.Plan.HostAction.ActionID = "debian.role.collect"
			raw, _ := json.Marshal(roleInput)
			x.Plan.HostAction.ActionInput = string(raw)
			x.Plan.HostAction.ActionInputDigest = hostaction.BytesDigest([]byte(x.Plan.HostAction.ActionInput))
			x.Measurement.ConfigurationDigest = x.Plan.HostAction.ActionInputDigest
			var err error
			x.Plan.HostRoleScope, err = linuxrole.ScopeForRequest(*x.Plan.HostAction)
			if err != nil {
				t.Fatal(err)
			}
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
		ids, e := gate.RequiredHostControls(s.Profile, stage)
		if e != nil {
			t.Fatal(e)
		}
		for _, id := range ids {
			digest, e := gate.HostControlProofDigest(s, id, stage, at)
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

func replacementCanonicalReceipt(x store.HostAdmissionMeasurement) generated.ExecutionReceipt {
	p := admissionCanonicalPlan(x.Plan)
	key := x.Plan.PlanID + "-" + x.Receipt.OperationID
	r := x.Result
	r.ControlMeasurements = []generated.AccessMeasurement{x.Measurement}
	r.ResultDigest = hostaction.ResultDigest(r)
	receipt := x.Receipt
	receipt.PlanID = p.PlanID
	receipt.PlanDigest = p.PlanDigest
	receipt.RunID = "run-" + p.PlanID
	receipt.StepID = "step-" + key
	receipt.LeaseID = "lease-" + key
	receipt.ReceiptID = "receipt-" + key
	receipt.ResultDigest = r.ResultDigest
	return receipt
}
func replacementPersistedRoleFixture(t *testing.T, at *time.Time, stateless ...bool) roleAdmissionFixture {
	expected := replacementQualifiedRoleSnapshot(t, *at, stateless...)
	return replacementPersistRoleSnapshot(t, at, expected, "initial-role-declaration", 1, nil)
}

func replacementPersistRoleSnapshot(t *testing.T, at *time.Time, expected store.HostAdmissionSnapshot, roleDeclaration string, intentRevision int64, existing *roleAdmissionFixture, prepared ...generated.Plan) roleAdmissionFixture {
	var access generated.DebianAccessInput
	json.Unmarshal([]byte(expected.Measurements[0].Plan.HostAccessSequence.Actions[0].ActionInput), &access)
	// Recovery references the exact canonical receipt that the shared fixture
	// persists, including its final plan/run/step identities.
	mappingDigest := ""
	for i := range expected.Measurements {
		x := &expected.Measurements[i]
		if x.Measurement.Volume == nil {
			continue
		}
		if x.Measurement.Volume.Kind == "mapping" {
			mappingDigest = hostaction.Digest(replacementCanonicalReceipt(*x))
			continue
		}
		var in generated.VolumeRecoveryInput
		json.Unmarshal([]byte(x.Plan.HostAction.ActionInput), &in)
		in.PriorVolumeReceiptDigest = mappingDigest
		raw, _ := json.Marshal(in)
		x.Plan.HostAction.ActionInput = string(raw)
		x.Plan.HostAction.ActionInputDigest = hostaction.BytesDigest(raw)
		x.Plan.HostAction.TargetDigest = hostaction.Digest(admissionTargetDraft(access, in.HostID))
		x.Plan.HostAction.ConsoleConfirmation.TargetDigest = x.Plan.HostAction.TargetDigest
		x.Plan.Operations[0].TargetID = in.HostID
		x.Receipt.TargetID = in.HostID
		x.Plan.Operations[0].ArtifactDigest = hostaction.Digest(*x.Plan.HostAction)
		x.Receipt.ArtifactDigest = x.Plan.Operations[0].ArtifactDigest
		var err error
		x.Plan.HostBaselineScope, err = debianbaseline.ScopeForRequest(*x.Plan.HostAction)
		if err != nil {
			t.Fatal(err)
		}
		x.Measurement.Volume.PriorVolumeReceiptDigest = mappingDigest
		resealHostMeasurement(&expected, x)
		expected.Results[i] = x.Control
	}
	prepare := func(f admissionSQL, input generated.DebianAccessInput) {
		for _, x := range expected.Measurements {
			if x.Measurement.Volume != nil && x.Measurement.Volume.Kind == "mapping" {
				b := x.Measurement.Volume.Binding
				f.host(input, b.RecoveryCustodianID, b.RecoveryCustodianIdentityDigest)
				f.host(input, b.ControlHostID, b.ControlHostIdentityDigest)
				break
			}
		}
		// Record an exact old role apply intent predating all the current collected
		// evidence. This is an actual canonical plan/step row, not a readiness flag.
		for _, x := range expected.Measurements {
			if x.Plan.HostRoleScope != nil {
				var p generated.Plan
				json.Unmarshal(f.bytes(x.Plan), &p)
				p.PlanID = "initial-role-intent"
				p.DeclarationID = roleDeclaration
				p.Binding.StateRevision = intentRevision
				p.HostAction.ActionID = "debian.role.apply"
				p.Operations[0].OperationID = "initial-role"
				p.Operations[0].ArtifactDigest = hostaction.Digest(*p.HostAction)
				if len(prepared) > 0 {
					p = prepared[0]
				} else {
					p = admissionCanonicalPlan(p)
				}
				r := x.Receipt
				r.PlanID = p.PlanID
				r.PlanDigest = p.PlanDigest
				r.RunID = roleDeclaration + "-run"
				r.StepID = roleDeclaration + "-step"
				r.LeaseID = roleDeclaration + "-lease"
				r.ReceiptID = roleDeclaration + "-receipt"
				r.OperationID = p.Operations[0].OperationID
				r.ArtifactDigest = p.Operations[0].ArtifactDigest
				var existingRuns int
				if existing != nil {
					if err := existing.db.QueryRow(`SELECT count(*) FROM plan_runs WHERE plan_id=? AND status='succeeded'`, p.PlanID).Scan(&existingRuns); err != nil {
						t.Fatal(err)
					}
				}
				if existingRuns == 0 {
					f.receipt(p, r)
				}
				break
			}
		}
		for _, x := range expected.Measurements {
			if x.Measurement.Volume != nil && x.Measurement.Volume.Kind == "mapping" {
				b := x.Measurement.Volume.Binding
				reason := hostaction.Digest("volume-declaration")
				d := generated.DeclarationRevision{Schema: generated.SchemaIDDeclarationRevision, SchemaVersion: "1.0.0", DeclarationID: b.DeclarationID, DeclarationType: "host.volume", Revision: 1, StateRevision: 1, Status: "draft", CreatedAt: at.Format(time.RFC3339), CreatedBy: "human-a", AgentSessionID: "fixture", Operations: []generated.DeclarationOperation{{Sequence: 1, OperationID: "declare-volume", OperationType: "host.volume", AdapterID: "core.host-action", TargetID: input.HostID, InputDigest: hostaction.Digest(b), ArtifactDigest: hostaction.Digest(b), Idempotent: true}}, Extensions: []generated.ContractExtension{{Name: "x-host-volume-binding", ValueDigest: hostaction.Digest(b)}}}
				semantic := struct {
					DeclarationID   string                           `json:"declarationId"`
					DeclarationType string                           `json:"declarationType"`
					Operations      []generated.DeclarationOperation `json:"operations"`
					ReasonDigest    string                           `json:"reasonDigest"`
					Extensions      []generated.ContractExtension    `json:"extensions"`
				}{d.DeclarationID, d.DeclarationType, d.Operations, reason, d.Extensions}
				d.ContentDigest = hostaction.Digest(semantic)
				f.exec(`INSERT INTO declaration_revisions VALUES(?,1,?,1,0,?,?,'draft',?,?,'human-a','fixture')`, d.DeclarationID, d.DeclarationType, d.ContentDigest, reason, f.bytes(d), d.CreatedAt)
			}
		}
	}
	if existing != nil {
		return seedHostAdmissionFixture(t, at, expected, prepare, existing.authority, existing.db, existing.proofs, false)
	}
	return newHostAdmissionFixture(t, at, expected, prepare)
}

func TestReplacementPersistedRoleAdmission(t *testing.T) {
	at := time.Now().UTC().Truncate(time.Second)
	f := replacementPersistedRoleFixture(t, &at)
	s, e := f.repo.ResolveHostAdmission(f.ctx, f.input.HostID)
	if e != nil {
		t.Fatal("resolve", e)
	}
	p, e := f.repo.GetAppliedProfileScope(f.ctx)
	if e != nil {
		t.Fatal(e)
	}
	scope := gate.ResolvedScope{ProfileID: p.ProfileID, ProfileVersion: p.ProfileVersion, PolicyID: p.PolicyID, PolicyVersion: p.PolicyVersion, Capabilities: p.Capabilities, StateRevision: p.StateRevision, RecoveryEpoch: p.RecoveryEpoch}
	got, e := gate.EvaluateHostAdmission(context.Background(), s, scope, "host.role-admission", at)
	if e != nil || got.Outcome != "passed" {
		t.Fatalf("role admission status=%s reason=%v baselineBlockers=%v roleBlockers=%v error=%v", got.Outcome, got.ReasonCode, s.Blockers, s.RoleBlockers, e)
	}
}

// These operations are fixture composition of real store/gate seams, not effect
// mocks. The root separately tests server wiring and real recovery composition.
type replacementIntegrationOperations struct {
	f    roleAdmissionFixture
	repo *store.HostReplacementRepository
	at   *time.Time
}

func (o replacementIntegrationOperations) ApplyReplacement(ctx context.Context, p generated.Plan, x store.HostReplacementExecution) (string, error) {
	ctx, e := o.f.authority.HostRunReadContext(ctx, x.RunID)
	if e != nil {
		return "", e
	}
	switch p.Operations[0].OperationType {
	case hostreplacement.AliasClaimOperation:
		s, e := o.f.repo.ResolveHostAdmission(ctx, p.HostAliasClaim.HostID)
		if e != nil {
			return "", e
		}
		profile, e := o.f.repo.GetAppliedProfileScope(ctx)
		if e != nil {
			return "", e
		}
		scope := gate.ResolvedScope{ProfileID: profile.ProfileID, ProfileVersion: profile.ProfileVersion, PolicyID: profile.PolicyID, PolicyVersion: profile.PolicyVersion, Capabilities: profile.Capabilities, StateRevision: profile.StateRevision, RecoveryEpoch: profile.RecoveryEpoch}
		g, e := gate.EvaluateHostAdmission(ctx, s, scope, "host.role-admission", *o.at)
		if e != nil {
			return "", e
		}
		if g.Outcome != "passed" {
			return "", errors.New(g.ReasonCode)
		}
		if _, e = o.repo.ClaimAliases(ctx, x, s); e != nil {
			return "", e
		}
	case hostreplacement.CommitOperation:
		o.f.seed.t.Log("commit: resolving current role admission")
		s, e := o.f.repo.ResolveHostAdmission(ctx, p.HostReplacement.NewHostID)
		if e != nil {
			o.f.seed.t.Logf("commit failure: %v", e)
			return "", e
		}
		profile, e := o.f.repo.GetAppliedProfileScope(ctx)
		if e != nil {
			o.f.seed.t.Logf("commit failure: %v", e)
			return "", e
		}
		scope := gate.ResolvedScope{ProfileID: profile.ProfileID, ProfileVersion: profile.ProfileVersion, PolicyID: profile.PolicyID, PolicyVersion: profile.PolicyVersion, Capabilities: profile.Capabilities, StateRevision: profile.StateRevision, RecoveryEpoch: profile.RecoveryEpoch}
		g, e := gate.EvaluateHostAdmission(ctx, s, scope, "host.role-admission", *o.at)
		if e != nil {
			o.f.seed.t.Logf("commit failure: %v", e)
			return "", e
		}
		if g.Outcome != "passed" {
			o.f.seed.t.Logf("commit failure: %v", e)
			o.f.seed.t.Logf("commit admission denied: %s baseline=%v role=%v", g.ReasonCode, s.Blockers, s.RoleBlockers)
			return "", errors.New(g.ReasonCode)
		}
		o.f.seed.t.Log("commit: common role gate passed; verifying fresh qualified fence")
		if e = recordHostReplacementFenceFixture(o.f.seed.t, ctx, o.f.authority, o.repo, x, *o.at); e != nil {
			o.f.seed.t.Logf("commit failure: %v", e)
			return "", e
		}
		o.f.seed.t.Log("commit: qualified fence recorded; applying transactional ownership CAS")
		if _, e = o.repo.Commit(ctx, store.HostReplacementCommit{Execution: x, Admission: s}); e != nil {
			o.f.seed.t.Logf("commit failure: %v", e)
			return "", e
		}
	case hostreplacement.FreezeOperation:
		if _, e = o.repo.Freeze(ctx, x); e != nil {
			return "", e
		}
	default:
		return "", errors.New("unsupported fixture operation")
	}
	if e = o.repo.VerifyExecution(ctx, x, p.Operations[0].OperationType); e != nil {
		return "", e
	}
	// Digest the exact durable ownership history created by this execution.
	var raw []byte
	if e = o.f.db.QueryRow(`SELECT event_bytes FROM host_alias_history WHERE json_extract(event_bytes,'$.Execution.PlanID')=? AND json_extract(event_bytes,'$.Execution.RunID')=? ORDER BY event_ordinal DESC LIMIT 1`, x.PlanID, x.RunID).Scan(&raw); e != nil {
		return "", e
	}
	return hostaction.BytesDigest(raw), nil
}
func (o replacementIntegrationOperations) VerifyReplacement(ctx context.Context, p generated.Plan, x store.HostReplacementExecution, _ string) error {
	return o.repo.VerifyExecution(ctx, x, p.Operations[0].OperationType)
}

func TestReplacementAPIClaimAndFreezeApprovedPipeline(t *testing.T) {
	runReplacementPipeline(t, nil, nil)
}

// RunReplacementBrowserAcceptance is test-only reuse for the external-package
// acceptance that supplies the real server browser boundary.
func RunReplacementBrowserAcceptance(t *testing.T, transport lifecycleBrowserTransport, gate lifecycleDiscoveryGate) {
	runReplacementPipeline(t, transport, gate)
}

func runReplacementPipeline(t *testing.T, transport lifecycleBrowserTransport, discoveryGate lifecycleDiscoveryGate) {
	at := time.Now().UTC().Truncate(time.Second)
	clock := func() time.Time { return at }
	var f roleAdmissionFixture
	var upstreamTarget *generated.HostDiscoveryTargetDraftRequest
	var upstreamRole *generated.Plan
	if transport == nil {
		f = replacementPersistedRoleFixture(t, &at, true)
	} else {
		existing, target := lifecycleAdoptedFixture(t, &at, transport, discoveryGate)
		upstreamTarget = &target
		ops, requests := admissionAccessSequenceForInput(t, existing.input, true, target)
		baseline := qualifiedHostSnapshotFromSequence(t, at, ops, requests)
		namespaceReplacementSnapshot(&baseline, "upstream-baseline", 0)
		existing.seed.exec(`UPDATE system_meta SET state_revision=100 WHERE id=1`)
		existing.seed.exec(`INSERT INTO gate_applied_profiles(binding_id,profile_id,profile_version,policy_id,policy_version,capabilities_bytes,state_revision,recovery_epoch,declaration_id,declaration_revision,plan_id,plan_digest,run_id,step_id,lease_id,human_id,applied_at) VALUES('scope-a','vegastack-labs','1.0.0','policy-a','1.0.0',X'5B5D',1,0,'scope-declaration',1,'scope-plan',?,'scope-run','scope-step','scope-lease','human-a',?)`, hostaction.Digest("scope"), at.Format(time.RFC3339))
		existing = seedHostAdmissionFixture(t, &at, baseline, nil, existing.authority, existing.db, existing.proofs, false)
		expected := replacementQualifiedRoleSnapshotForInput(t, at, existing.input, "application", target)
		var desired generated.LinuxRoleInput
		for _, m := range expected.Measurements {
			if m.Plan.HostRoleScope != nil {
				if json.Unmarshal([]byte(m.Plan.HostAction.ActionInput), &desired) != nil {
					t.Fatal("desired role")
				}
				break
			}
		}
		applied := lifecycleApplyRole(t, existing, &at, target, desired, transport)
		upstreamRole = &applied
		namespaceReplacementSnapshot(&expected, "post-role", applied.Binding.StateRevision)
		existing.seed.exec(`UPDATE system_meta SET state_revision=? WHERE id=1`, applied.Binding.StateRevision+100)
		f = replacementPersistRoleSnapshot(t, &at, expected, applied.DeclarationID, applied.Binding.StateRevision, &existing, applied)
	}
	seedDiscoveryCredential := func(input generated.DebianAccessInput, host string) {
		draft := admissionTargetDraft(input, host)
		fingerprint := hostaction.Digest("synthetic-public-key-" + host)
		f.seed.exec(`INSERT INTO credential_reference_versions VALUES(?,?, 'core.host-discovery','host.discovery.read',?,'native-systemd','version-a',?,'active',1,0,?,?,'fixture-credential',1,'fixture-credential-plan',?,'fixture-credential-run','fixture-credential-step','fixture-credential-lease','human-a',?)`, "discovery-version-"+host, draft.Target.CredentialReferenceID, draft.Target.TargetID, fingerprint, at.Format(time.RFC3339), []byte(`["core.host-discovery"]`), hostaction.Digest("synthetic-credential-plan-"+host), at.Format(time.RFC3339))
	}
	seedDiscoveryCredential(f.input, f.input.HostID)
	policy := store.NewEffectiveAuthorizationRepository(f.authority)
	evaluator := authorization.NewEvaluator(policy)
	n := 0
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "1.0.0", ReleaseBuildID: "build-a"}, func() (string, error) { n++; return fmt.Sprintf("replacement-api-%d", n), nil })
	app, e := NewApplication(Config{Authority: f.authority, Authorizer: allowOperationAuthorizer(), Reads: testReads{}, Results: factory, Cursors: testCursor{}})
	if e != nil {
		t.Fatal(e)
	}
	serve := func(method, path string, input any) *httptest.ResponseRecorder {
		return serveGateRequest(t, app, method, path, input)
	}
	if transport != nil {
		app.config.Authorizer = store.NewReadAuthorizer(f.authority)
		app.config.Reads = store.NewReadRepository(f.authority)
		serve = transport(app, f.authority, f.db, at)
	}
	auth := EffectiveAuthorizationConfig{Authorizer: evaluator, Recorder: policy, Clock: clock}
	app.effective = auth
	declarations, e := change.NewService(store.NewDeclarationRepository(f.authority), clock)
	if e != nil {
		t.Fatal(e)
	}
	replacements := store.NewHostReplacementRepository(f.authority)
	if err := replacements.ConfigureAdmission(f.repo); err != nil {
		t.Fatal(err)
	}
	revisions := store.NewPlanRepository(f.authority)
	observations, e := planengine.NewStateObservationReader(revisions)
	if e != nil {
		t.Fatal(e)
	}
	plans, e := planengine.NewService(planengine.Config{HostActions: store.NewHostActionRepository(f.authority), HostActionCredentials: store.NewCredentialRepository(f.authority), HostReplacements: replacements, Repository: revisions, Observations: observations, Clock: clock, PolicyVersion: "1.0.0", ToolVersion: "1.0.0", ContractVersion: "1.0.0", Risk: "infrastructure", AuthorizationBranch: "human", ExecutorMode: "central", OperationExecutorID: "executor-central"})
	if e != nil {
		t.Fatal(e)
	}
	if e = RegisterDeclarationPlanOperations(app, DeclarationPlanConfig{Declarations: declarations, Plans: plans, Results: factory, Authorization: auth}); e != nil {
		t.Fatal(e)
	}
	if e = RegisterHostReplacementOperations(app, HostReplacementOperations{Replacements: replacements, Declarations: declarations, Results: factory}); e != nil {
		t.Fatal(e)
	}
	if transport != nil {
		if err := RegisterGateOperations(app, GateOperations{Gates: f.repo, Revisions: revisions, Declarations: declarations, Results: factory, Clock: clock}); err != nil {
			t.Fatal(err)
		}
		f.seed.exec(`INSERT INTO read_grants VALUES('human-a','gate.read','gate','host.role-admission',1,'active','now','now')`)
	}
	browserRoleAdmission := func(host string) {
		t.Helper()
		if transport == nil {
			return
		}
		w := serve(http.MethodGet, "/api/v1/gates/host.role-admission?subjectId="+host, nil)
		var response struct{ Data generated.GateView }
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &response) != nil || response.Data.Evaluation.Outcome != "passed" || response.Data.Evaluation.SubjectID != host {
			t.Fatalf("browser role admission %s: %d %s", host, w.Code, w.Body.String())
		}
	}
	browserRoleAdmission(f.input.HostID)
	grant := func(id, action, cap, kind, target string, branch any) {
		f.seed.exec(`INSERT INTO effective_authorization_grants VALUES(?,'human-a','control-plane-admin',?,?,?,?,?,1,'active','now','now')`, id, action, cap, kind, target, branch)
	}
	ack, e := acknowledgement.NewService(acknowledgement.Config{Repository: store.NewAcknowledgementRepository(f.authority), Plans: roleTestPlans{plans}, Authorizer: evaluator, Clock: clock})
	if e != nil {
		t.Fatal(e)
	}
	effects := &runengine.HostReplacementEffect{Operations: replacementIntegrationOperations{f, replacements, &at}, Approvals: store.NewAcknowledgementRepository(f.authority)}
	runs := store.NewRunRepository(f.authority)
	registry := adapter.NewRegistry()
	engineConfig := runengine.Config{Repository: runs, Plans: plans, Admission: runengine.NewAdmissionGate(ack, clock), Adapters: registry, Core: runengine.CoreRouter{HostReplacement: effects}, Clock: clock}
	if transport != nil {
		hosts := store.NewHostActionRepository(f.authority)
		credentials := store.NewCredentialRepository(f.authority)
		readiness := roleTestReadiness{f.repo, clock}
		runs.ConfigureHostRoles(f.repo, readiness)
		if err := registry.Register(hostaction.AdapterID, &roleTestOS{authority: f.authority, hosts: hosts, clock: clock}); err != nil {
			t.Fatal(err)
		}
		if err := registry.RegisterCredentialResolver(adapter.CredentialCapabilityScope{ResolverID: "native-systemd", ConsumerID: hostaction.AdapterID, ProfileID: "synthetic-role-profile", CapabilityID: "synthetic-role-ssh", Enabled: true}, roleTestCredential{}); err != nil {
			t.Fatal(err)
		}
		engineConfig.SecretGate = roleTestSecretGate{hosts}
		engineConfig.CredentialStep = &runengine.CredentialStep{Bindings: credentials, Resolvers: registry, Profiles: roleTestCredential{}, Plans: plans, Clock: clock}
		if err := RegisterHostActionOperations(app, HostActionOperations{Hosts: hosts, Declarations: declarations, Credentials: credentials, RolePreparer: readiness, Results: factory}); err != nil {
			t.Fatal(err)
		}
	}
	engine, e := runengine.NewEngine(engineConfig)
	if e != nil {
		t.Fatal(e)
	}
	if transport != nil {
		if e = RegisterRunOperations(app, RunOperationConfig{Runs: engine, Plans: revisions, Acknowledgements: ack, Results: factory, Authorization: auth}); e != nil {
			t.Fatal(e)
		}
	}
	if transport != nil {
		registerLifecycleBrowserApproval(t, app, ack, plans, factory)
	}
	execute := func(declarationID string) generated.Run {
		t.Helper()
		doc, e := declarations.Get(f.ctx, declarationID, 1)
		if e != nil {
			t.Fatal(e)
		}
		rev, e := revisions.CurrentRevision(f.ctx)
		if e != nil {
			t.Fatal(e)
		}
		finger, e := observations.CurrentFingerprint(f.ctx, doc.DeclarationID, doc.Operations)
		if e != nil {
			t.Fatal(e)
		}
		request := generated.PlanCreateRequest{Schema: generated.SchemaIDPlanCreateRequest, SchemaVersion: "1.0.0", DeclarationID: doc.DeclarationID, DeclarationRevision: 1, ExpectedStateRevision: rev.StateRevision, RecoveryEpoch: rev.RecoveryEpoch, ObservationFingerprint: finger, IdempotencyKey: "plan-" + declarationID, Extensions: doc.Extensions}
		var p generated.Plan
		if transport != nil {
			grant("plan-"+declarationID, "author", "plan.author", "declaration", doc.DeclarationID, nil)
			w := serve(http.MethodPost, "/api/v1/declarations/"+doc.DeclarationID+"/plans", request)
			if w.Code != 200 {
				t.Fatalf("browser plan: %d %s", w.Code, w.Body.String())
			}
			var response struct{ Data generated.PlanPresentation }
			if json.Unmarshal(w.Body.Bytes(), &response) != nil {
				t.Fatal("browser plan response")
			}
			p = response.Data.Plan
		} else {
			made, err := plans.Create(f.ctx, planengine.AuthorScope{PrincipalID: "human-a", PrincipalMethod: identity.LocalOSPeerMethod, AgentSessionID: "replacement-integration"}, request)
			if err != nil {
				t.Fatal("plan", err)
			}
			p = made.Plan
		}
		target := p.Operations[0].TargetID
		grant("execute-"+declarationID, "execute", p.Operations[0].OperationType, "execution-target", target, "human")
		grant("ack-"+declarationID, "acknowledge", "plan.acknowledge", "plan-target", target, "human")
		if transport != nil {
			ref := generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: p.PlanID, PlanDigest: p.PlanDigest, RecoveryEpoch: p.Binding.RecoveryEpoch, IdempotencyKey: "run-" + declarationID, Extensions: []generated.ContractExtension{}}
			grant("read-plan-"+declarationID, "read", "plan.read", "plan", p.PlanID, nil)
			f.seed.exec(`INSERT INTO read_grants VALUES('human-a','plan.read','plan',?,1,'active','now','now')`, p.PlanID)
			fetched := serve(http.MethodGet, "/api/v1/plans/"+p.PlanID, nil)
			var readPlan struct{ Data generated.PlanPresentation }
			if fetched.Code != 200 || json.Unmarshal(fetched.Body.Bytes(), &readPlan) != nil || readPlan.Data.Plan.PlanDigest != p.PlanDigest {
				t.Fatalf("missing-ack plan precondition: %d %s", fetched.Code, fetched.Body.String())
			}
			denied := serve(http.MethodPost, "/api/v1/plans/"+p.PlanID+"/execute", ref)
			if denied.Code != http.StatusNotFound || !strings.Contains(denied.Body.String(), "RESOURCE_NOT_FOUND") {
				t.Fatalf("missing acknowledgement accepted: %d %s", denied.Code, denied.Body.String())
			}
			var runCount int
			if err := f.db.QueryRow(`SELECT count(*) FROM plan_runs WHERE plan_id=?`, p.PlanID).Scan(&runCount); err != nil || runCount != 0 {
				t.Fatalf("missing acknowledgement created run count=%d error=%v", runCount, err)
			}
			stale := ref
			stale.PlanDigest = hostaction.Digest("stale-browser-plan")
			denied = serve(http.MethodPost, "/api/v1/plans/"+p.PlanID+"/execute", stale)
			if denied.Code < 400 || !strings.Contains(denied.Body.String(), "PLAN_STALE") {
				t.Fatalf("stale plan accepted: %d %s", denied.Code, denied.Body.String())
			}
			f.seed.exec(`UPDATE effective_authorization_grants SET status='revoked' WHERE grant_id=?`, "execute-"+declarationID)
			denied = serve(http.MethodPost, "/api/v1/plans/"+p.PlanID+"/execute", ref)
			if denied.Code != http.StatusForbidden {
				t.Fatalf("revoked grant accepted: %d %s", denied.Code, denied.Body.String())
			}
			f.seed.exec(`INSERT INTO effective_authorization_grants VALUES(?,'human-a','infrastructure-admin','execute',?,'execution-target',?,'human',1,'active','now','now')`, "execute-restored-"+declarationID, p.Operations[0].OperationType, target)
		}
		var approved generated.Acknowledgement
		if transport != nil {
			requestLifecycleBrowserApproval(t, serve, f.seed, p, &at)
		} else {
			at = time.Now().UTC().Truncate(time.Second)
			human := identity.Principal{ID: "human-a", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}
			card, e := ack.Request(f.ctx, acknowledgement.Scope{Human: human, AuthorityID: "fixture-authority", Nonce: "nonce-" + declarationID}, p.PlanID)
			if e != nil {
				t.Fatal(e)
			}
			approved = approveHostLifecycleViaSlack(t, ack, card)

		}
		if transport != nil {
			ref := generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: p.PlanID, PlanDigest: p.PlanDigest, RecoveryEpoch: p.Binding.RecoveryEpoch, IdempotencyKey: "run-" + declarationID, Extensions: []generated.ContractExtension{}}
			response := serve(http.MethodPost, "/api/v1/plans/"+p.PlanID+"/execute", ref)
			if response.Code != http.StatusOK {
				t.Fatalf("browser execute: %d %s", response.Code, response.Body.String())
			}
			var envelope struct{ Data generated.RunPresentation }
			if json.Unmarshal(response.Body.Bytes(), &envelope) != nil || envelope.Data.Run.Status != "succeeded" {
				t.Fatalf("browser run: %s", response.Body.String())
			}
			assertLifecycleDurableRun(t, f.db, p, envelope.Data.Run)
			return generated.Run{RunID: envelope.Data.Run.RunID, Status: envelope.Data.Run.Status}
		}
		branch := "human"
		decision := generated.AuthorizationDecision{Schema: generated.SchemaIDAuthorizationDecision, SchemaVersion: "1.0.0", DecisionID: "decision-" + declarationID, PrincipalID: "human-a", Action: "execute", TargetID: target, Allowed: true, Branch: &branch, ReasonCode: authorization.ReasonAllowed, GrantRevision: 1, PlanDigest: p.PlanDigest, DecidedAt: at.Format(time.RFC3339), Extensions: []generated.ContractExtension{}}
		owner := "human-a"
		run, e := engine.Submit(f.ctx, runengine.SubmitRequest{Reference: generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: p.PlanID, PlanDigest: p.PlanDigest, IdempotencyKey: "run-" + declarationID, Extensions: []generated.ContractExtension{}}, Authorization: decision, Acknowledgement: &approved, Attribution: audit.Attribution{AuthenticatedPrincipalID: owner, AuthenticatedPrincipalMethod: identity.LocalOSPeerMethod, ResponsibleHumanPrincipalID: &owner}})
		if e != nil || run.Status != "succeeded" {
			t.Fatalf("execute status%s error%v", run.Status, e)
		}
		return run
	}
	rev, e := revisions.CurrentRevision(f.ctx)
	if e != nil {
		t.Fatal(e)
	}
	claim := generated.HostAliasClaimRequest{Schema: generated.SchemaIDHostAliasClaimRequest, SchemaVersion: "1.0.0", HostID: f.input.HostID, HostIdentityDigest: f.input.HostIdentityDigest, AliasIDs: []string{"control-alias"}, ExpectedStateRevision: rev.StateRevision, RecoveryEpoch: rev.RecoveryEpoch, IdempotencyKey: "initial-alias"}
	d := hostaction.Digest(claim)
	decl := generated.DeclarationRevisionRequest{Schema: generated.SchemaIDDeclarationRevisionRequest, SchemaVersion: "1.0.0", DeclarationID: "initial-alias", DeclarationType: "host.alias-claim", ExpectedRevision: 1, ExpectedStateRevision: rev.StateRevision, RecoveryEpoch: rev.RecoveryEpoch, HostAliasClaim: &claim, ReasonDigest: d, Extensions: []generated.ContractExtension{{Name: hostreplacement.AliasClaimExtension, ValueDigest: d}}, Operations: []generated.DeclarationOperation{{Sequence: 1, OperationID: "claim", OperationType: hostreplacement.AliasClaimOperation, AdapterID: hostreplacement.AdapterID, TargetID: "initial-alias", InputDigest: d, ArtifactDigest: d, Idempotent: true}}}
	grant("prepare-"+f.input.HostID, "author", "host.replacement.prepare", "host", f.input.HostID, nil)
	grant("claim-author", "author", "declaration.author", "declaration", decl.DeclarationID, nil)
	w := serve(http.MethodPost, "/api/v1/declarations/initial-alias/revisions", decl)
	if transport != nil {
		if w.Code != http.StatusForbidden {
			t.Fatalf("browser alias-claim boundary: %d %s", w.Code, w.Body.String())
		}
		w = serveGateRequest(t, app, http.MethodPost, "/api/v1/declarations/initial-alias/revisions", decl)
	}
	if w.Code != 200 {
		t.Fatalf("claim HTTP%d %s", w.Code, w.Body.String())
	}
	execute(decl.DeclarationID)
	// Register independent synthetic target identity; no alias/ownership outcome is seeded.
	newInput := admissionAccessInput(t, "aide", "cryptsetup-bin")
	newInput.HostID = "replacement-host"
	newInput.ProfileID = f.input.ProfileID
	newInput.HostIdentityDigest = hostaction.Digest("replacement-machine")
	newInput.RollbackSpecification.HostID = newInput.HostID
	newInput.RollbackSpecification.HostIdentityDigest = newInput.HostIdentityDigest
	newInput.RollbackDigest = hostaction.Digest(newInput.RollbackSpecification)
	var replacementTarget *generated.HostDiscoveryTargetDraftRequest
	if transport != nil {
		next, target := lifecycleAdoptedFixture(t, &at, transport, discoveryGate, f)
		newInput = next.input
		replacementTarget = &target
	}

	if transport == nil {
		grant("read-new", "read", "host.read", "host", newInput.HostID, nil)
	}
	oldTarget := admissionTargetDraft(f.input, f.input.HostID)
	if upstreamTarget != nil {
		oldTarget = *upstreamTarget
	}
	newTarget := admissionTargetDraft(newInput, newInput.HostID)
	if replacementTarget != nil {
		newTarget = *replacementTarget
	}
	current, e := f.repo.ResolveHostAdmission(f.ctx, f.input.HostID)
	if e != nil {
		t.Fatal(e)
	}
	obs := generated.HostObservation{Schema: generated.SchemaIDHostObservation, SchemaVersion: "1.0.0", ObservationID: "observation-" + newInput.HostID, TargetID: newTarget.Target.TargetID, TargetRevision: 1, TargetDigest: hostaction.Digest(newTarget), Collector: "ssh", CollectorVersion: "1.0.0", ObservedAt: at.Format(time.RFC3339), ExpiresAt: at.Add(time.Hour).Format(time.RFC3339), Status: "untrusted", Facts: []generated.HostDiscoveryFact{}, Blockers: []string{}}
	obs.ContentDigest = hostaction.Digest("observed-new-host")
	if transport == nil {
		f.seed.host(newInput, newInput.HostID, newInput.HostIdentityDigest, obs)
	} else {
		host, err := store.NewHostAdoptionRepository(f.authority).Get(f.ctx, newInput.HostID)
		if err != nil {
			t.Fatal(err)
		}
		obs, err = store.NewHostDiscoveryRepository(f.authority).Get(f.ctx, host.ObservationID)
		if err != nil {
			t.Fatal(err)
		}
	}
	seedDiscoveryCredential(newInput, newInput.HostID)
	if transport != nil {
		ops, requests := admissionAccessSequenceForInput(t, newInput, true, newTarget)
		baseline := qualifiedHostSnapshotFromSequence(t, at, ops, requests)
		currentRevision, err := revisions.CurrentRevision(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		namespaceReplacementSnapshot(&baseline, "new-host-baseline", currentRevision.StateRevision)
		f.seed.exec(`UPDATE system_meta SET state_revision=? WHERE id=1`, currentRevision.StateRevision+100)
		seedHostAdmissionFixture(t, &at, baseline, nil, f.authority, f.db, f.proofs, false)
		f.seed.exec(`INSERT INTO effective_authorization_principals VALUES('automation-a','agent','active',1,'now','now')`)
		f.seed.exec(`INSERT INTO effective_authorization_grants VALUES('new-role-automation','automation-a','infrastructure-admin','execute','host.action.execute','execution-target',?,'human',1,'active','now','now')`, newInput.HostID)
		grant("new-role-prepare", "author", "host.action.prepare", "host", newInput.HostID, nil)
		keyDigest := hostaction.Digest("synthetic-new-role-key")
		f.seed.exec(`INSERT INTO credential_reference_versions VALUES('new-role-action','new-role-action','host-action','host-action-ssh',?,'native-systemd','version-a',?,'active',1,0,?,?,'fixture-declaration',1,'fixture-plan',?,'fixture-run','fixture-step','fixture-lease','human-a','now')`, newInput.HostID, keyDigest, at.Format(time.RFC3339), []byte(`["host-action"]`), keyDigest)
	}
	role := roleTestInput(t, newInput)
	replacementApplicationRole(&role)
	role.BaselineSnapshotDigest = hostaction.Digest("replacement-current-baseline")
	role.RenderedPolicyDigest = linuxrole.PolicyDigest(role)
	role.RoleBindingDigest = linuxrole.RoleBindingDigest(role)
	if transport != nil {
		role.BaselineSnapshotDigest = ""
		var err error
		role, err = (roleTestReadiness{f.repo, clock}).PrepareRole(f.ctx, "debian.role.apply", role)
		if err != nil {
			t.Fatal("new role prepare", err)
		}
	}
	roleRaw, _ := json.Marshal(role)
	roleDeclRevision, e := revisions.CurrentRevision(f.ctx)
	if e != nil {
		t.Fatal(e)
	}
	roleReq := generated.HostActionRequest{Schema: generated.SchemaIDHostActionRequest, SchemaVersion: "1.0.0", HostID: newInput.HostID, TargetRevision: 1, TargetDigest: hostaction.Digest(newTarget), ActionID: "debian.role.apply", ActionVersion: "1.0.0", ActionInput: string(roleRaw), ActionInputDigest: hostaction.BytesDigest(roleRaw), CallerUID: role.AutomationUID, AutomationPrincipalID: "automation-a", CredentialReferenceID: "credential-a", CredentialMaterialVersion: "version-a", ConsoleConfirmation: generated.HostActionConsoleConfirmation{Schema: generated.SchemaIDHostActionConsoleConfirmation, SchemaVersion: "1.0.0", Method: "administrator-verified-console", TargetDigest: hostaction.Digest(newTarget), HostIdentityDigest: newInput.HostIdentityDigest}, ExpectedStateRevision: roleDeclRevision.StateRevision, RecoveryEpoch: roleDeclRevision.RecoveryEpoch, IdempotencyKey: "replacement-role"}
	if transport != nil {
		roleReq.CredentialReferenceID = "new-role-action"
	}
	roleID := hostaction.DraftID(roleReq)
	if err := hostaction.ValidateRequest(roleReq); err != nil {
		t.Fatalf("proposed role request: %v", err)
	}
	if transport == nil {
		f.seed.exec(`INSERT INTO host_action_drafts VALUES(?,?,?,'human-a',0,0)`, roleID, hostaction.Digest(roleReq), f.seed.bytes(roleReq))
		roleDigest := hostaction.Digest(roleReq)
		_, e = declarations.Revise(f.ctx, change.AuthorScope{PrincipalID: "human-a", PrincipalMethod: identity.LocalOSPeerMethod, AgentSessionID: "new-role-declaration"}, generated.DeclarationRevisionRequest{Schema: generated.SchemaIDDeclarationRevisionRequest, SchemaVersion: "1.0.0", DeclarationID: roleID, DeclarationType: "host.action", ExpectedRevision: 1, ExpectedStateRevision: roleDeclRevision.StateRevision, RecoveryEpoch: roleDeclRevision.RecoveryEpoch, ReasonDigest: roleDigest, Extensions: []generated.ContractExtension{{Name: "x-host-action", ValueDigest: roleDigest}}, Operations: []generated.DeclarationOperation{{Sequence: 1, OperationID: "new-role", OperationType: hostaction.OperationType, AdapterID: hostaction.AdapterID, TargetID: newInput.HostID, InputDigest: roleDigest, ArtifactDigest: roleDigest, Idempotent: false}}})
		if e != nil {
			t.Fatal("new role declaration", e)
		}

	} else {
		grant("new-role-draft", "author", "declaration.author", "declaration", roleID, nil)
		w := serve(http.MethodPost, "/api/v1/host-actions/draft", roleReq)
		if w.Code != 200 {
			t.Fatalf("new role draft: %d %s", w.Code, w.Body.String())
		}
		var submission struct {
			Data generated.HostActionSubmission
		}
		if json.Unmarshal(w.Body.Bytes(), &submission) != nil || submission.Data.DeclarationID != roleID || submission.Data.OriginalRequestDigest != hostaction.Digest(roleReq) {
			t.Fatalf("new role request binding %s", w.Body.String())
		}
	}
	// Prepare and execute the independent new-host role before freezing the old
	// owner. Credential manifests and plans bind the exact current revision; an
	// unrelated intervening mutation requires fresh preparation. Only external
	// host observations are synthetic; the browser plan, Slack and run are real.
	roleDoc, err := declarations.Get(f.ctx, roleID, 1)
	if err != nil {
		t.Fatal(err)
	}
	roleRevision, err := revisions.CurrentRevision(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	roleFingerprint, err := observations.CurrentFingerprint(f.ctx, roleID, roleDoc.Operations)
	if err != nil {
		t.Fatal(err)
	}
	rolePlanRequest := generated.PlanCreateRequest{Schema: generated.SchemaIDPlanCreateRequest, SchemaVersion: "1.0.0", DeclarationID: roleID, DeclarationRevision: 1, ExpectedStateRevision: roleRevision.StateRevision, RecoveryEpoch: roleRevision.RecoveryEpoch, ObservationFingerprint: roleFingerprint, IdempotencyKey: "new-role-plan", Extensions: roleDoc.Extensions}
	var rolePlan store.PlanCommitResult
	if transport != nil {
		grant("new-role-plan", "author", "plan.author", "declaration", roleID, nil)
		w := serve(http.MethodPost, "/api/v1/declarations/"+roleID+"/plans", rolePlanRequest)
		var response struct{ Data generated.PlanPresentation }
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &response) != nil {
			t.Fatalf("new role browser plan: %d %s", w.Code, w.Body.String())
		}
		rolePlan.Plan = response.Data.Plan
	} else {
		rolePlan, err = plans.Create(f.ctx, planengine.AuthorScope{PrincipalID: "human-a", PrincipalMethod: identity.LocalOSPeerMethod, AgentSessionID: "replacement-role-fixture"}, rolePlanRequest)
		if err != nil {
			t.Fatal("new role plan", err)
		}
	}
	grant("new-role-execute", "execute", hostaction.OperationType, "execution-target", newInput.HostID, "human")
	grant("new-role-ack", "acknowledge", "plan.acknowledge", "plan-target", newInput.HostID, "human")
	if transport != nil {
		requestLifecycleBrowserApproval(t, serve, f.seed, rolePlan.Plan, &at)
	} else {
		at = time.Now().UTC().Truncate(time.Second)
		roleHuman := identity.Principal{ID: "human-a", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}
		roleCard, err := ack.Request(f.ctx, acknowledgement.Scope{Human: roleHuman, AuthorityID: "fixture-authority", Nonce: "new-role-nonce"}, rolePlan.Plan.PlanID)
		if err != nil {
			t.Fatal(err)
		}
		approveHostLifecycleViaSlack(t, ack, roleCard)

	}
	if transport != nil {
		w := serve(http.MethodPost, "/api/v1/plans/"+rolePlan.Plan.PlanID+"/execute", generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: rolePlan.Plan.PlanID, PlanDigest: rolePlan.Plan.PlanDigest, RecoveryEpoch: rolePlan.Plan.Binding.RecoveryEpoch, IdempotencyKey: "execute-new-role", Extensions: []generated.ContractExtension{}})
		if w.Code != 200 {
			t.Fatalf("new role execution %d %s", w.Code, w.Body.String())
		}
		var response struct{ Data generated.RunPresentation }
		if json.Unmarshal(w.Body.Bytes(), &response) != nil || response.Data.Run.Status != "succeeded" {
			t.Fatalf("new role run %s", w.Body.String())
		}
		assertLifecycleDurableRun(t, f.db, rolePlan.Plan, response.Data.Run)
	}

	newExpected := replacementQualifiedRoleSnapshotForInput(t, at, newInput, "application", newTarget)
	offset := rolePlan.Plan.Binding.StateRevision - 1
	namespaceReplacementSnapshot(&newExpected, newInput.HostID, offset)
	f.seed.exec(`UPDATE system_meta SET state_revision=? WHERE id=1`, offset+100)
	replacementPersistRoleSnapshot(t, &at, newExpected, roleID, rolePlan.Plan.Binding.StateRevision, &f, rolePlan.Plan)
	browserRoleAdmission(newInput.HostID)
	rev, e = revisions.CurrentRevision(f.ctx)
	if e != nil {
		t.Fatal(e)
	}
	oldKey, _ := hostreplacement.SSHHostKeyDigest(oldTarget.Target.HostKey)
	newKey, _ := hostreplacement.SSHHostKeyDigest(newTarget.Target.HostKey)
	req := replacementAPIInput()
	req.ReplacementID = "replace-control"
	req.OldHostID = f.input.HostID
	req.NewHostID = newInput.HostID
	req.OldIdentityDigest = f.input.HostIdentityDigest
	req.NewIdentityDigest = newInput.HostIdentityDigest
	req.OldTargetDigest = hostaction.Digest(oldTarget)
	req.NewTargetDigest = hostaction.Digest(newTarget)
	req.OldSSHHostKeyDigest = oldKey
	req.NewSSHHostKeyDigest = newKey
	req.ProfileID = f.input.ProfileID
	req.ProfileLockDigest = f.input.ProfileLockDigest
	req.OldRoleBindingDigest = current.RoleBindingDigest
	req.RoleDeclarationID = "initial-role-declaration"
	if upstreamRole != nil {
		req.RoleDeclarationID = upstreamRole.DeclarationID
		req.RoleDeclarationRevision = upstreamRole.Binding.DeclarationRevision
	}
	req.ProposedRoleDeclarationID = roleID
	req.ProposedRoleBindingDigest = role.RoleBindingDigest
	req.PreservedPreimageDigest = hostreplacement.RolePreimageDigest(role)
	req.AliasBindings = []generated.HostReplacementAliasBinding{{Schema: generated.SchemaIDHostReplacementAliasBinding, SchemaVersion: "1.0.0", AliasID: "control-alias", OwnerHostID: req.OldHostID, OwnerIdentityDigest: req.OldIdentityDigest, OwnerRevision: 1, OwnershipGeneration: 1}}
	req.VolumeIDs = append([]string{}, current.VolumeIDs...)
	rows, err := f.db.Query(`SELECT DISTINCT d.declaration_id FROM declaration_revisions d, json_each(d.canonical_bytes,'$.operations') o WHERE d.status!='superseded' AND NOT EXISTS(SELECT 1 FROM declaration_revisions n WHERE n.declaration_id=d.declaration_id AND n.declaration_revision>d.declaration_revision) AND json_extract(o.value,'$.targetId')=? AND json_extract(o.value,'$.adapterId')!='core.gate' AND (d.declaration_type='host.volume' OR EXISTS(SELECT 1 FROM immutable_plans p JOIN plan_runs r ON r.plan_id=p.plan_id JOIN plan_run_steps step ON step.run_id=r.run_id WHERE p.declaration_id=d.declaration_id AND step.target_id=? AND step.effect_state IN ('intent-recorded','receipt-recorded','effect-unknown','verified'))) ORDER BY d.declaration_id`, req.OldHostID, req.OldHostID)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		req.ResourceIDs = append(req.ResourceIDs, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	rows.Close()
	req.ExpectedStateRevision = rev.StateRevision
	req.OSPreparation = generated.HostReplacementOsPreparation{Schema: generated.SchemaIDHostReplacementOsPreparation, SchemaVersion: "1.0.0", Method: "administrator-prepared", ObservationID: obs.ObservationID, ObservationDigest: obs.ContentDigest, HostIdentityDigest: req.NewIdentityDigest, ConfirmedAt: at.Format(time.RFC3339)}
	for _, id := range []string{req.NewHostID} {
		grant("prepare-"+id, "author", "host.replacement.prepare", "host", id, nil)
	}
	draftID := "host-replacement-" + hostaction.Digest(req)[7:39]
	grant("replace-author", "author", "declaration.author", "declaration", draftID, nil)
	w = serve(http.MethodPost, "/api/v1/host-replacements", req)
	if w.Code != 200 {
		t.Fatalf("replacement HTTP%d %s", w.Code, w.Body.String())
	}
	execute(draftID)
	state, e := replacements.Get(f.ctx, req.ReplacementID)
	if e != nil || state.Status != "frozen" {
		t.Fatalf("freeze state%+v err%v", state, e)
	}
	if _, e = f.repo.ResolveHostAdmission(f.ctx, req.OldHostID); e == nil {
		t.Fatal("frozen old host retained admission")
	}
	var owner string
	var revision int64
	if e = f.db.QueryRow(`SELECT owner_host_id,owner_revision FROM host_alias_owners WHERE alias_id='control-alias'`).Scan(&owner, &revision); e != nil || owner != req.OldHostID || revision != 2 {
		t.Fatal("freeze reassigned or lost owner", owner, revision, e)
	}
	// A continuation cannot rewrite the frozen identity or owner preconditions.
	for name, mutate := range map[string]func(*generated.HostReplacementRequest){
		"changed-alias-owner-revision": func(q *generated.HostReplacementRequest) {
			q.AliasBindings = append([]generated.HostReplacementAliasBinding{}, q.AliasBindings...)
			q.AliasBindings[0].OwnerRevision++
		},
		"omitted-owned-resource": func(q *generated.HostReplacementRequest) { q.ResourceIDs = append([]string{}, q.ResourceIDs[1:]...) },
		"changed-preserved-preimage": func(q *generated.HostReplacementRequest) {
			q.PreservedPreimageDigest = hostaction.Digest("unapproved-preimage")
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := req
			bad.Operation = "commit"
			bad.ExpectedDeclarationRevision = state.DeclarationRevision
			current, err := revisions.CurrentRevision(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			bad.ExpectedStateRevision = current.StateRevision
			bad.IdempotencyKey = name
			mutate(&bad)
			badID := "host-replacement-" + hostaction.Digest(bad)[7:39]
			grant("deny-"+name, "author", "declaration.author", "declaration", badID, nil)
			response := serve(http.MethodPost, "/api/v1/host-replacements", bad)
			if response.Code < 400 || response.Code >= 500 {
				t.Fatalf("invalid continuation HTTP%d %s", response.Code, response.Body.String())
			}
			var drafts int
			if err := f.db.QueryRow(`SELECT count(*) FROM host_replacement_drafts WHERE operation='commit'`).Scan(&drafts); err != nil || drafts != 0 {
				t.Fatalf("denied continuation staged: %d %v", drafts, err)
			}
			still, err := replacements.Get(f.ctx, req.ReplacementID)
			if err != nil || still.Status != "frozen" {
				t.Fatalf("denial changed freeze: %+v %v", still, err)
			}
		})
	}
	commit := req
	commit.Operation = "commit"
	commit.IdempotencyKey = "commit-replacement"
	commit.ExpectedDeclarationRevision = state.DeclarationRevision
	commitRevision, err := revisions.CurrentRevision(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	commit.ExpectedStateRevision = commitRevision.StateRevision
	commitID := "host-replacement-" + hostaction.Digest(commit)[7:39]
	grant("commit-author", "author", "declaration.author", "declaration", commitID, nil)
	w = serve(http.MethodPost, "/api/v1/host-replacements", commit)
	if w.Code != 200 {
		t.Fatalf("commit draft HTTP%d %s", w.Code, w.Body.String())
	}
	execute(commitID)
	state, err = replacements.Get(f.ctx, req.ReplacementID)
	if err != nil || state.Status != "committed" {
		t.Fatalf("commit state=%+v err=%v", state, err)
	}
	if err := f.db.QueryRow(`SELECT owner_host_id,owner_revision FROM host_alias_owners WHERE alias_id='control-alias'`).Scan(&owner, &revision); err != nil || owner != req.NewHostID || revision != 3 {
		t.Fatalf("committed owner=%s revision=%d err=%v", owner, revision, err)
	}
	if _, err := f.repo.ResolveHostAdmission(f.ctx, req.OldHostID); err == nil {
		t.Fatal("retired old host regained admission")
	}
	w = serve(http.MethodGet, "/api/v1/host-replacements/"+req.ReplacementID, nil)
	if w.Code != 200 {
		t.Fatalf("state HTTP%d %s", w.Code, w.Body.String())
	}
}

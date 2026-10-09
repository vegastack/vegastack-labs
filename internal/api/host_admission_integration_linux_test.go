//go:build linux

package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/debianaccess"
	"github.com/vegastack/vegastack-labs/internal/debianbaseline"
	"github.com/vegastack/vegastack-labs/internal/gate"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/store"
	"golang.org/x/crypto/ssh"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

// This intentionally incomplete registered-host fixture proves that registration
// and applied deployment scope cannot substitute for actual host producer proof.
// Its rows are test-only; it makes no claim of native qualification.
func TestHostAdmissionAPIRegistrationDoesNotAdmit(t *testing.T) {
	app, _, revisions, path := gateAPIFixture(t)
	db, err := sql.Open("sqlite3", "file:"+path+"?mode=rw")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := db.Exec(query, args...); err != nil {
			t.Fatal(err)
		}
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	seed := admissionSQL{t, db}
	in := admissionAccessInput(t)
	in.HostID = "host-a"
	seed.host(in, "host-a", digest)
	exec(`UPDATE system_meta SET state_revision=1 WHERE id=1`)
	exec(`INSERT INTO effective_authorization_principals VALUES('human-a','human','active',1,'2026-09-15T08:00:00Z','2026-09-15T08:00:00Z')`)
	exec(`INSERT INTO effective_authorization_grants VALUES('read-host','human-a','reader','read','host.read','host','host-a',NULL,1,'active','2026-09-15T08:00:00Z','2026-09-15T08:00:00Z')`)
	exec(`INSERT INTO gate_applied_profiles(binding_id,profile_id,profile_version,policy_id,policy_version,capabilities_bytes,state_revision,recovery_epoch,declaration_id,declaration_revision,plan_id,plan_digest,run_id,step_id,lease_id,human_id,applied_at) VALUES('scope-a','vegastack-labs','1.0.0','policy-a','1.0.0',X'5B5D',1,0,'scope-declaration',1,'scope-plan',?,'scope-run','scope-step','scope-lease','human-a','2026-09-15T08:00:00Z')`, digest)
	before, err := revisions.CurrentRevision(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, gateID := range []string{"host.hardening-baseline", "host.role-admission"} {
		t.Run(gateID, func(t *testing.T) {
			def, ok := gateDefinition(gateID)
			if !ok {
				t.Fatal("gate absent")
			}
			check := generated.GateCheckRequest{Schema: generated.SchemaIDGateCheckRequest, SchemaVersion: "1.0.0", ExpectedStateRevision: before.StateRevision, RecoveryEpoch: before.RecoveryEpoch, TargetDigest: digest, IdempotencyKey: "check-a", GateID: gateID, SubjectID: "host-a", DefinitionVersion: def.DefinitionVersion}
			checked := serveGateRequest(t, app, http.MethodPost, "/api/v1/gates/"+gateID+"/check", check)
			viewed := serveGateRequest(t, app, http.MethodGet, "/api/v1/gates/"+gateID+"?subjectId=host-a", nil)
			listed := serveGateRequest(t, app, http.MethodGet, "/api/v1/gates?subjectId=host-a", nil)
			for _, response := range []struct {
				code int
				body []byte
			}{{checked.Code, checked.Body.Bytes()}, {viewed.Code, viewed.Body.Bytes()}, {listed.Code, listed.Body.Bytes()}} {
				if response.code != http.StatusOK {
					t.Fatalf("response %d: %s", response.code, response.body)
				}
			}
			var c struct{ Data generated.GateEvaluation }
			var v struct{ Data generated.GateView }
			var l struct{ Data generated.GateListData }
			if json.Unmarshal(checked.Body.Bytes(), &c) != nil || json.Unmarshal(viewed.Body.Bytes(), &v) != nil || json.Unmarshal(listed.Body.Bytes(), &l) != nil {
				t.Fatal("invalid envelope")
			}
			if c.Data.Outcome != "blocked" || !strings.HasPrefix(c.Data.ReasonCode, "host-") {
				t.Fatalf("registration admitted or left unbound: %+v", c.Data)
			}
			if v.Data.Evaluation.Outcome != c.Data.Outcome || v.Data.Evaluation.ReasonCode != c.Data.ReasonCode {
				t.Fatal("get/check differ")
			}
			found := false
			for _, item := range l.Data.Gates {
				if item.Definition.GateID == gateID {
					found = true
					if item.Evaluation.Outcome != c.Data.Outcome || item.Evaluation.ReasonCode != c.Data.ReasonCode {
						t.Fatal("list/check differ")
					}
				}
			}
			if !found {
				t.Fatal("list omitted gate")
			}
		})
	}
	after, err := revisions.CurrentRevision(context.Background())
	if err != nil || after != before {
		t.Fatalf("read changed authority: %+v %v", after, err)
	}
}

// admissionSQL writes synthetic canonical producer receipts to an isolated test
// database. Production has no equivalent setter; the API must still perform all
// current-row joins and evaluate every proof before returning a positive result.
type admissionSQL struct {
	t  *testing.T
	db interface {
		Exec(string, ...any) (sql.Result, error)
	}
}

func (f admissionSQL) exec(q string, args ...any) {
	f.t.Helper()
	if _, err := f.db.Exec(q, args...); err != nil {
		f.t.Fatalf("fixture SQL: %v\n%s", err, q)
	}
}
func (f admissionSQL) bytes(v any) []byte {
	f.t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		f.t.Fatal(e)
	}
	return b
}
func (f admissionSQL) plan(p generated.Plan) {
	f.declaration(p)
	d := hostaction.Digest(p.PlanID)
	f.exec(`INSERT OR IGNORE INTO immutable_plans VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, p.PlanID, p.PlanDigest, p.DeclarationID, p.Binding.DeclarationRevision, p.Binding.StateRevision, p.Binding.RecoveryEpoch, d, d, d, f.bytes(p), "synthetic test plan", p.ReadableDigest, "2026-01-01T00:00:00Z", "2026-12-01T00:00:00Z")
}
func (f admissionSQL) receipt(p generated.Plan, r generated.ExecutionReceipt) {
	f.plan(p)
	d := hostaction.Digest(r.RunID)
	f.exec(`INSERT OR IGNORE INTO plan_runs VALUES(?,?,?,'decision',NULL,'1.0.0','central','executor',?,'succeeded',0,'not-requested','verified',?,0,?,?,?, ?,?,'now','now')`, r.RunID, p.PlanID, p.PlanDigest, d, d, p.Binding.StateRevision, p.Binding.RecoveryEpoch, d, d, []byte(`{}`))
	var op generated.PlanOperation
	for _, candidate := range p.Operations {
		if candidate.OperationID == r.OperationID {
			op = candidate
			break
		}
	}
	f.exec(`INSERT OR IGNORE INTO plan_run_steps(step_id,run_id,sequence,operation_id,operation_type,adapter_id,executor_id,target_id,input_digest,artifact_digest,idempotent,status,effect_state,active_lease_id,result_digest,started_at,finished_at) VALUES(?,?,?,?,?,?,'executor',?,?,?,1,'succeeded','verified',?,?,'now','now')`, r.StepID, r.RunID, op.Sequence, r.OperationID, op.OperationType, r.AdapterID, r.TargetID, r.ArtifactDigest, r.ArtifactDigest, r.LeaseID, r.ResultDigest)
	f.exec(`INSERT INTO target_execution_leases(lease_id,run_id,step_id,target_id,binding_digest,nonce_digest,recovery_epoch,claimed_at,renew_after,expires_at,maximum_expires_at,status,canonical_bytes) VALUES(?,?,?,?,?,?,?,'now','later','later','later','released',?)`, r.LeaseID, r.RunID, r.StepID, r.TargetID, r.BindingDigest, r.NonceDigest, r.RecoveryEpoch, []byte(`{}`))
	f.exec(`INSERT INTO execution_receipts VALUES(?,?,?,?,?,?,?,?)`, r.ReceiptID, r.LeaseID, r.RunID, r.StepID, r.Status, r.ResultDigest, f.bytes(r), r.RecordedAt)
}

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
	controls, e := gate.RequiredHostControls(s.Profile, "baseline")
	if e != nil {
		t.Fatal(e)
	}
	for _, id := range controls {
		digest, e := gate.HostControlProofDigest(s, id, "baseline", at)
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

func admissionAccessInput(t *testing.T) generated.DebianAccessInput {
	t.Helper()
	public, _, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	key, e := ssh.NewPublicKey(public)
	if e != nil {
		t.Fatal(e)
	}
	k := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	d := hostaction.BytesDigest([]byte("synthetic-qualified-lock"))
	a := generated.AccessAccount{Schema: generated.SchemaIDAccessAccount, SchemaVersion: "1.0.0", Name: "automation", UID: 1001, GID: 1001, Home: "/home/automation", Role: "automation", PublicKeys: []string{k}, PublicKeyDigests: []string{hostaction.BytesDigest([]byte(k))}}
	lock := generated.DebianProfileLock{Schema: generated.SchemaIDDebianProfileLock, SchemaVersion: "1.0.0", ImageDigest: d, OSFamily: "debian", OSVersion: "13.6", Architecture: "amd64", PackageSourceDigest: d, Packages: []generated.AccessPackage{{Schema: generated.SchemaIDAccessPackage, SchemaVersion: "1.0.0", Name: "openssh-server", Version: "synthetic-test"}}, ExecutableVersion: "1.0.0", AnsibleVersion: "synthetic-test", AnsibleExecutableDigest: d, CollectionDigest: d, RoleDigest: d, Backend: "iptables-nft"}
	for _, name := range []string{"fail2ban", "python3-systemd", "auditd", "apparmor", "apparmor-utils", "apt", "systemd", "procps"} {
		lock.Packages = append(lock.Packages, generated.AccessPackage{Schema: generated.SchemaIDAccessPackage, SchemaVersion: "1.0.0", Name: name, Version: "synthetic-test"})
	}
	in := generated.DebianAccessInput{Schema: generated.SchemaIDDebianAccessInput, SchemaVersion: "1.0.0", HostID: "test-host", HostIdentityDigest: d, ProfileID: "test-profile", ProfileLock: lock, ProfileLockDigest: hostaction.Digest(lock), ActionVersion: "1.0.0", AutomationUID: 1001, Accounts: []generated.AccessAccount{a}, SSHUsers: []string{"automation"}, SSHSourcePrefixes: []string{"192.0.2.0/24"}, RecoverySourcePrefixes: []string{"192.0.2.1/32"}, PrivilegedServiceKeys: []generated.AccessServiceKey{}, Interfaces: []generated.AccessInterface{{Schema: generated.SchemaIDAccessInterface, SchemaVersion: "1.0.0", Name: "eth0", Index: 2, Addresses: []string{"192.0.2.2"}}}, HostFlows: []generated.AccessFlow{}, ContainerFlows: []generated.AccessFlow{}}
	in.RollbackSpecification = generated.AccessRollbackSpecification{Schema: generated.SchemaIDAccessRollbackSpecification, SchemaVersion: "1.0.0", HostID: in.HostID, HostIdentityDigest: d, ProfileLockDigest: in.ProfileLockDigest, DeadlineSeconds: 600, RecoverySourcePrefixes: in.RecoverySourcePrefixes, OwnedState: []generated.AccessOwnedState{{Schema: generated.SchemaIDAccessOwnedState, SchemaVersion: "1.0.0", ResourceID: "ssh-config", BeforeDigest: d, AfterDigest: d}}}
	in.RollbackDigest = hostaction.Digest(in.RollbackSpecification)
	in.RenderedAccess = generated.RenderedAccess{Schema: generated.SchemaIDRenderedAccess, SchemaVersion: "1.0.0", ProfileLockDigest: in.ProfileLockDigest, RendererDigest: d, Accounts: in.Accounts, SSHUsers: in.SSHUsers, SSHSourcePrefixes: in.SSHSourcePrefixes, RecoverySourcePrefixes: in.RecoverySourcePrefixes, PrivilegedServiceKeys: in.PrivilegedServiceKeys, Interfaces: in.Interfaces, HostFlows: in.HostFlows, ContainerFlows: in.ContainerFlows, RollbackUnitsDigest: d}
	in.RenderedAccessDigest = hostaction.Digest(in.RenderedAccess)
	return in
}
func admissionAccessSequence(t *testing.T) ([]generated.PlanOperation, []generated.HostActionRequest) {
	in := admissionAccessInput(t)
	raw, _ := json.Marshal(in)
	d := hostaction.Digest(admissionTargetDraft(in, in.HostID))
	apply := generated.HostActionRequest{Schema: generated.SchemaIDHostActionRequest, SchemaVersion: "1.0.0", ActionID: "debian.access.apply", ActionVersion: "1.0.0", ActionInput: string(raw), ActionInputDigest: hostaction.BytesDigest(raw), HostID: in.HostID, TargetRevision: 1, TargetDigest: d, AutomationPrincipalID: "automation", CallerUID: 1001, CredentialReferenceID: "action-key", CredentialMaterialVersion: "version-a", ConsoleConfirmation: generated.HostActionConsoleConfirmation{Schema: generated.SchemaIDHostActionConsoleConfirmation, SchemaVersion: "1.0.0", Method: "administrator-verified-console", TargetDigest: d, HostIdentityDigest: in.HostIdentityDigest}, ExpectedStateRevision: 1, RecoveryEpoch: 0, IdempotencyKey: "apply-a"}
	collect := apply
	collect.ActionID = "debian.access.collect"
	collect.IdempotencyKey = "collect-a"
	source := generated.AccessProbeSource{Schema: generated.SchemaIDAccessProbeSource, SchemaVersion: "1.0.0", HostID: in.HostID, IdentityDigest: in.HostIdentityDigest, Kind: "host-network", ContextID: "test-context", ContextDigest: d, Interface: "eth0", InterfaceIndex: 2, Address: "192.0.2.1", Family: "ipv4", RouteDigest: d}
	tuple := generated.AccessProbeTuple{Schema: generated.SchemaIDAccessProbeTuple, SchemaVersion: "1.0.0", HostID: in.HostID, IdentityDigest: in.HostIdentityDigest, Address: "192.0.2.2", Port: 22, Protocol: "tcp"}
	probe := generated.AccessProbeInput{Schema: generated.SchemaIDAccessProbeInput, SchemaVersion: "1.0.0", SubjectHostID: in.HostID, SubjectIdentityDigest: in.HostIdentityDigest, SubjectHostKey: in.Accounts[0].PublicKeys[0], ProfileLockDigest: in.ProfileLockDigest, ApplyInputDigest: apply.ActionInputDigest, RollbackDigest: in.RollbackDigest, AdministratorUser: "automation", Source: source, Cases: []generated.AccessProbeCase{}, TimeoutMillis: 10, Attempts: 1}
	for i, kind := range []string{"ssh-admin", "ssh-wrong-user", "ssh-password", "ssh-root", "host-flow", "host-flow"} {
		expected := "denied"
		if i == 0 || i == 4 {
			expected = "allowed"
		}
		destination := tuple
		if i == 5 {
			destination.Port = 1
		}
		probe.Cases = append(probe.Cases, generated.AccessProbeCase{Schema: generated.SchemaIDAccessProbeCase, SchemaVersion: "1.0.0", ProbeID: fmt.Sprintf("probe-%d", i), Kind: kind, Expected: expected, Destination: destination, Witness: tuple})
	}
	local := apply
	local.ActionID = "debian.access.probe.local"
	raw, _ = json.Marshal(probe)
	local.ActionInput = string(raw)
	local.ActionInputDigest = hostaction.BytesDigest(raw)
	local.IdempotencyKey = "local-a"
	probe.Source.HostID = "source-host"
	probe.Source.IdentityDigest = hostaction.Digest("source-host")
	probe.Source.Kind = "network-namespace"
	probe.Source.Address = "198.51.100.2"
	probe.Cases = []generated.AccessProbeCase{{Schema: generated.SchemaIDAccessProbeCase, SchemaVersion: "1.0.0", ProbeID: "probe-source", Kind: "ssh-source", Expected: "denied", Destination: tuple, Witness: tuple}}
	remote := apply
	remote.HostID = probe.Source.HostID
	remote.TargetDigest = hostaction.Digest(admissionTargetDraft(in, remote.HostID))
	remote.ConsoleConfirmation.TargetDigest = remote.TargetDigest
	remote.ConsoleConfirmation.HostIdentityDigest = probe.Source.IdentityDigest
	remote.ActionID = "debian.access.probe-source"
	remote.IdempotencyKey = "source-a"
	raw, _ = json.Marshal(probe)
	remote.ActionInput = string(raw)
	remote.ActionInputDigest = hostaction.BytesDigest(raw)
	requests := []generated.HostActionRequest{apply, collect, local, remote}
	ops := []generated.PlanOperation{}
	seq := generated.HostAccessSequence{SubjectHostID: apply.HostID, SubjectIdentityDigest: in.HostIdentityDigest, ProfileLockDigest: in.ProfileLockDigest, ApplyOperationID: "apply", ApplyDraftDigest: hostaction.Digest(apply), ProbeSteps: []generated.HostAccessProbeStep{}}
	for i, r := range requests {
		opID := fmt.Sprintf("step-%d", i)
		if i == 0 {
			opID = "apply"
		}
		kind := "collect"
		if i == 2 {
			kind = "local-probe"
		}
		if i == 3 {
			kind = "source-probe"
		}
		typ := hostaction.OperationType
		if i == 2 {
			typ = debianaccess.LocalProbeOperation
		}
		ops = append(ops, generated.PlanOperation{Sequence: int64(i + 1), OperationID: opID, OperationType: typ, AdapterID: hostaction.AdapterID, ExecutorID: "executor-central", TargetID: r.HostID, InputDigest: d, ArtifactDigest: hostaction.Digest(r)})
		if i > 0 {
			context := in.HostIdentityDigest
			if i > 1 {
				context = source.ContextDigest
			}
			seq.ProbeSteps = append(seq.ProbeSteps, generated.HostAccessProbeStep{Schema: generated.SchemaIDHostAccessProbeStep, SchemaVersion: "1.0.0", OperationID: opID, Kind: kind, SourceHostID: r.HostID, SourceIdentityDigest: r.ConsoleConfirmation.HostIdentityDigest, SourceContextDigest: context, DraftDigest: hostaction.Digest(r), SpecificationDigest: r.ActionInputDigest})
		}
	}
	confirm := apply
	confirm.ActionID = "debian.access.confirm"
	confirm.IdempotencyKey = "confirm-a"
	raw, _ = json.Marshal(generated.AccessConfirmInput{Schema: generated.SchemaIDAccessConfirmInput, SchemaVersion: "1.0.0", HostID: in.HostID, HostIdentityDigest: in.HostIdentityDigest, ProfileLockDigest: in.ProfileLockDigest, RollbackDigest: in.RollbackDigest, ApplyOperationID: "apply", ApplyDraftDigest: seq.ApplyDraftDigest, ApplyInputDigest: apply.ActionInputDigest, ProbeSpecificationDigest: debianaccess.SequenceSpecificationDigest(seq)})
	confirm.ActionInput = string(raw)
	confirm.ActionInputDigest = hostaction.BytesDigest(raw)
	requests = append(requests, confirm)
	ops = append(ops, generated.PlanOperation{Sequence: 5, OperationID: "confirm", OperationType: hostaction.OperationType, AdapterID: hostaction.AdapterID, ExecutorID: "executor-central", TargetID: confirm.HostID, InputDigest: d, ArtifactDigest: hostaction.Digest(confirm)})
	return ops, requests
}

func validAppliedFixture(at time.Time) generated.GateEvidence {
	digest := "sha256:" + strings.Repeat("a", 64)
	return generated.GateEvidence{Schema: generated.SchemaIDGateEvidence, SchemaVersion: "1.1.0", EvidenceID: "evidence-a", GateID: "platform-safety", SubjectID: "site-a", DefinitionVersion: "1.0.0", EvaluatorVersion: "1.0.0", ReleaseBuildID: "build-a", ToolVersion: "1.0.0", ProfileID: "vegastack-labs", ProfileVersion: "1.0.0", PolicyID: "policy-a", PolicyVersion: "1.0.0", DeclarationID: "decl-a", DeclarationRevision: 1, StateRevision: 3, SourceKind: "local", ProofClass: "live", CollectorID: "collector-a", HumanID: "human-a", ArtifactDigest: digest, BundleDigest: digest, ObservedAt: at.Add(-time.Minute).Format(time.RFC3339), AppliedAt: at.Add(-30 * time.Second).Format(time.RFC3339), ExpiresAt: at.Add(time.Hour).Format(time.RFC3339), RecoveryEpoch: 0, Status: "applied"}
}

func admissionTargetDraft(in generated.DebianAccessInput, host string) generated.HostDiscoveryTargetDraftRequest {
	address := "192.0.2.2"
	if host != "test-host" {
		address = "198.51.100.2"
	}
	target := generated.HostDiscoveryTarget{Schema: generated.SchemaIDHostDiscoveryTarget, SchemaVersion: "1.0.0", TargetID: "target-" + host, Revision: 1, Address: address, Port: 22, User: "inspect", HostKey: in.Accounts[0].PublicKeys[0], ProfileID: in.ProfileID, CredentialReferenceID: "credential-a", MaterialVersion: "version-a", ExpectedOS: "debian", ExpectedVersion: "13.6", ExpectedArchitecture: "amd64"}
	return generated.HostDiscoveryTargetDraftRequest{Schema: generated.SchemaIDHostDiscoveryTargetDraftRequest, SchemaVersion: "1.0.0", Target: target, Action: "activate", IdempotencyKey: "target-" + host}
}

type admissionSyntheticProvenance struct {
	proofs map[string]store.HostEvidenceProvenance
}

func (v admissionSyntheticProvenance) VerifyHostEvidence(_ store.HostAdmissionSnapshot, e generated.GateEvidence, b generated.GateEvidenceBundle) (store.HostEvidenceProvenance, error) {
	if e.BundleDigest != hostaction.Digest(b) {
		return store.HostEvidenceProvenance{}, fmt.Errorf("fixture binding")
	}
	return v.proofs[e.EvidenceID], nil
}

func (f admissionSQL) declaration(p generated.Plan) {
	ops := []generated.DeclarationOperation{}
	for i, o := range p.Operations {
		ops = append(ops, generated.DeclarationOperation{Sequence: int64(i + 1), OperationID: o.OperationID, OperationType: o.OperationType, AdapterID: o.AdapterID, TargetID: o.TargetID, InputDigest: o.InputDigest, ArtifactDigest: o.ArtifactDigest, Idempotent: true})
	}
	d := hostaction.Digest("reason")
	doc := generated.DeclarationRevision{Schema: generated.SchemaIDDeclarationRevision, SchemaVersion: "1.0.0", DeclarationID: p.DeclarationID, DeclarationType: "host.action", Revision: 1, StateRevision: p.Binding.StateRevision, RecoveryEpoch: 0, Status: "draft", Operations: ops, CreatedAt: "2026-09-15T08:00:00Z", CreatedBy: "human-a", AgentSessionID: "test-session", Extensions: []generated.ContractExtension{}}
	semantic := struct {
		DeclarationID   string                           `json:"declarationId"`
		DeclarationType string                           `json:"declarationType"`
		Operations      []generated.DeclarationOperation `json:"operations"`
		ReasonDigest    string                           `json:"reasonDigest"`
		Extensions      []generated.ContractExtension    `json:"extensions"`
	}{doc.DeclarationID, doc.DeclarationType, ops, d, doc.Extensions}
	doc.ContentDigest = hostaction.Digest(semantic)
	f.exec(`INSERT OR IGNORE INTO declaration_revisions VALUES(?,1,?,?,0,?,?,'draft',?,'2026-09-15T08:00:00Z','human-a','test-session')`, doc.DeclarationID, doc.DeclarationType, doc.StateRevision, doc.ContentDigest, d, f.bytes(doc))
}

func TestHostAdmissionAPICurrentProofAndInvalidation(t *testing.T) {
	at := time.Date(2026, 9, 15, 8, 0, 0, 0, time.UTC)
	fixture := newRoleAdmissionFixture(t, &at)
	authority, db, f, repo, ctx, snapshot, input, expected, proofs := fixture.authority, fixture.db, fixture.seed, fixture.repo, fixture.ctx, fixture.snapshot, fixture.input, fixture.expected, fixture.proofs
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "1.0.0", ReleaseBuildID: "build-a"}, func() (string, error) { return "host-api-test", nil })
	app, err := NewApplication(Config{Authority: authority, Authorizer: allowOperationAuthorizer(), Reads: testReads{}, Results: factory, Cursors: testCursor{}})
	if err != nil {
		t.Fatal(err)
	}
	effective := &effectiveAuthorizationStub{}
	app.effective = EffectiveAuthorizationConfig{Authorizer: effective, Recorder: effective, Clock: func() time.Time { return at }}
	declarations, err := change.NewService(store.NewDeclarationRepository(authority), func() time.Time { return at })
	if err != nil {
		t.Fatal(err)
	}
	if err := RegisterGateOperations(app, GateOperations{Gates: repo, Revisions: store.NewPlanRepository(authority), Declarations: declarations, Results: factory, Clock: func() time.Time { return at }}); err != nil {
		t.Fatal(err)
	}
	check := func(want string) generated.GateEvaluation {
		t.Helper()
		token, e := store.NewPlanRepository(authority).CurrentRevision(ctx)
		if e != nil {
			t.Fatal(e)
		}
		def, _ := gateDefinition("host.hardening-baseline")
		request := generated.GateCheckRequest{Schema: generated.SchemaIDGateCheckRequest, SchemaVersion: "1.0.0", ExpectedStateRevision: token.StateRevision, RecoveryEpoch: token.RecoveryEpoch, TargetDigest: snapshot.BindingDigest, IdempotencyKey: "check-current", GateID: def.GateID, SubjectID: input.HostID, DefinitionVersion: def.DefinitionVersion}
		response := serveGateRequest(t, app, http.MethodGet, "/api/v1/gates/host.hardening-baseline?subjectId="+input.HostID, nil)
		var body struct{ Data generated.GateView }
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &body) != nil || body.Data.Evaluation.Outcome != want {
			t.Fatalf("want %s: %d %s", want, response.Code, response.Body.String())
		}
		checked := serveGateRequest(t, app, http.MethodPost, "/api/v1/gates/host.hardening-baseline/check", request)
		var c struct{ Data generated.GateEvaluation }
		if checked.Code != http.StatusOK || json.Unmarshal(checked.Body.Bytes(), &c) != nil || c.Data.Outcome != want || c.Data.ReasonCode != body.Data.Evaluation.ReasonCode {
			t.Fatalf("check differs: %d %s", checked.Code, checked.Body.String())
		}
		listed := serveGateRequest(t, app, http.MethodGet, "/api/v1/gates?subjectId="+input.HostID, nil)
		var l struct{ Data generated.GateListData }
		if listed.Code != http.StatusOK || json.Unmarshal(listed.Body.Bytes(), &l) != nil {
			t.Fatalf("list: %d %s", listed.Code, listed.Body.String())
		}
		found := false
		for _, v := range l.Data.Gates {
			if v.Definition.GateID == def.GateID {
				found = true
				if v.Evaluation.Outcome != want || v.Evaluation.ReasonCode != body.Data.Evaluation.ReasonCode {
					t.Fatalf("list differs: %+v", v.Evaluation)
				}
			}
		}
		if !found {
			t.Fatal("host gate omitted")
		}
		return body.Data.Evaluation
	}
	check("passed")
	savedNative := proofs.proofs["native-baseline"]
	delete(proofs.proofs, "native-baseline")
	check("blocked")
	proofs.proofs["native-baseline"] = savedNative
	check("passed")
	// Time alone invalidates a once-current proof without a mutation or host access.
	at = at.Add(25 * time.Hour)
	check("blocked")
	at = at.Add(-25 * time.Hour)
	check("passed")
	f.exec(`UPDATE system_meta SET state_revision=101 WHERE id=1`)
	check("passed")
	// A current declared volume with no mapping/custody observation is a
	// role blocker, while the independently proven baseline remains usable.
	volumeDigest := hostaction.Digest("unverified-volume-binding")
	volumeDoc := generated.DeclarationRevision{Schema: generated.SchemaIDDeclarationRevision, SchemaVersion: "1.0.0", DeclarationID: "pending-volume", DeclarationType: "host.volume", Revision: 1, StateRevision: 101, Status: "draft", Operations: []generated.DeclarationOperation{{Sequence: 1, OperationID: "volume", OperationType: "host.action.execute", AdapterID: "host-action-ssh", TargetID: input.HostID, InputDigest: volumeDigest, ArtifactDigest: volumeDigest}}, CreatedAt: at.Format(time.RFC3339), CreatedBy: "human-a", AgentSessionID: "volume-test", Extensions: []generated.ContractExtension{{Name: "x-host-volume-binding", ValueDigest: volumeDigest}}}
	volumeSemantic := struct {
		DeclarationID   string                           `json:"declarationId"`
		DeclarationType string                           `json:"declarationType"`
		Operations      []generated.DeclarationOperation `json:"operations"`
		ReasonDigest    string                           `json:"reasonDigest"`
		Extensions      []generated.ContractExtension    `json:"extensions"`
	}{volumeDoc.DeclarationID, volumeDoc.DeclarationType, volumeDoc.Operations, volumeDigest, volumeDoc.Extensions}
	volumeDoc.ContentDigest = hostaction.Digest(volumeSemantic)
	f.exec(`INSERT INTO declaration_revisions VALUES('pending-volume',1,'host.volume',101,0,?,?,'draft',?,?,'human-a','volume-test')`, volumeDoc.ContentDigest, volumeDigest, f.bytes(volumeDoc), volumeDoc.CreatedAt)
	check("passed")
	roleResponse := serveGateRequest(t, app, http.MethodGet, "/api/v1/gates/host.role-admission?subjectId="+input.HostID, nil)
	var roleBody struct{ Data generated.GateView }
	if roleResponse.Code != http.StatusOK || json.Unmarshal(roleResponse.Body.Bytes(), &roleBody) != nil || roleBody.Data.Evaluation.Outcome == "passed" {
		t.Fatalf("unqualified role admitted: %d %s", roleResponse.Code, roleResponse.Body.String())
	}
	// No role producer binding exists in this preparatory-host fixture. Exact
	// storage-only denial with a qualified role is covered by the owner tests.

	// More than 256 genuine old collections must not crowd out current proof.
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	history := admissionSQL{t, tx}
	var timeSync store.HostAdmissionMeasurement
	for _, x := range expected.Measurements {
		if x.Control.ControlID == "linux.time-sync" {
			timeSync = x
			break
		}
	}
	for i := 0; i < 257; i++ {
		history.measurement(timeSync, fmt.Sprintf("history-%03d", i), at.Add(-time.Hour), "passed")
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	check("passed")

	// Actual append-only native provenance: A passes, newer B passes, revoking
	// B without a supersedes link must not revive A. A fresh C may qualify anew.
	var native generated.GateEvidence
	for _, e := range expected.Evidence {
		if e.EvidenceID == "native-baseline" {
			native = e
			break
		}
	}
	nativeB := native
	nativeB.EvidenceID = "native-b"
	nativeB.DeclarationID = "evidence-native-b"
	nativeB.StateRevision = 90
	nativeBundle := expected.Bundles[native.EvidenceID]
	evidenceTx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	historicalEvidence := admissionSQL{t, evidenceTx}
	for i := 0; i < 65; i++ {
		old := native
		old.EvidenceID = fmt.Sprintf("historical-native-%02d", i)
		old.DeclarationID = "decl-" + old.EvidenceID
		old.StateRevision = int64(i + 1)
		old.ObservedAt = at.Add(-time.Hour).Format(time.RFC3339)
		old.AppliedAt = old.ObservedAt
		oldBundle := nativeBundle
		oldBundle.ObservedAt = old.ObservedAt
		historicalEvidence.evidence(old, oldBundle)
	}
	if err := evidenceTx.Commit(); err != nil {
		t.Fatal(err)
	}
	check("passed")
	f.evidence(nativeB, nativeBundle)
	qb := expected.Qualifications[0]
	qb.EvidenceID = nativeB.EvidenceID
	proofs.proofs[nativeB.EvidenceID] = store.HostEvidenceProvenance{Qualification: &qb}
	check("passed")
	revoked := nativeB
	revoked.EvidenceID = "native-b-revoked"
	revoked.DeclarationID = "evidence-native-b-revoked"
	revoked.StateRevision = 91
	revoked.Status = "revoked"
	revoked.RevokesEvidenceID = &nativeB.EvidenceID
	f.evidence(revoked, nativeBundle)
	check("blocked")
	nativeC := native
	nativeC.EvidenceID = "native-c"
	nativeC.DeclarationID = "evidence-native-c"
	nativeC.StateRevision = 92
	f.evidence(nativeC, nativeBundle)
	qc := expected.Qualifications[0]
	qc.EvidenceID = nativeC.EvidenceID
	proofs.proofs[nativeC.EvidenceID] = store.HostEvidenceProvenance{Qualification: &qc}
	check("passed")

	// A later failed measurement for the SAME current logical control overrides
	// its older positive receipt, then a fresh successful collection restores it.
	f.measurement(timeSync, "timesync-failed", at.Add(time.Second), "failed")
	at = at.Add(time.Second)
	if got := check("blocked"); got.ReasonCode != "host-control-failed:host.time-health" {
		t.Fatalf("latest failed control ignored: %+v", got)
	}
	f.measurement(timeSync, "timesync-refreshed", at, "passed")
	// Existing evidence references the old measurement digest, so recollection
	// alone is not approval of a changed proof bundle.
	check("blocked")

	// A later uncertain apply on another declaration must invalidate its
	// affected proof even though no replacement measurement was produced.
	var mutation generated.Plan
	for _, x := range expected.Measurements {
		if x.Control.ControlID == "linux.time-sync" {
			mutation = x.Plan
			break
		}
	}
	if mutation.HostAction == nil {
		t.Fatal("time-sync fixture missing")
	}
	request := *mutation.HostAction
	request.ActionID = "debian.baseline.apply"
	request.ExpectedStateRevision = 102
	mutation.HostAction = &request
	mutation.DeclarationID = "later-timesync-change"
	mutation.Binding.StateRevision = 102
	mutation.Operations[0].ArtifactDigest = hostaction.Digest(request)
	mutation = admissionCanonicalPlan(mutation)
	f.plan(mutation)
	md := hostaction.Digest("uncertain-time-sync")
	f.exec(`INSERT INTO plan_runs VALUES('uncertain-run',?,?,'decision',NULL,'1.0.0','central','executor',?,'interrupted',0,'not-requested','incomplete',NULL,0,102,0,?,?,?,'now','now')`, mutation.PlanID, mutation.PlanDigest, md, md, md, []byte(`{}`))
	f.exec(`INSERT INTO plan_run_steps(step_id,run_id,sequence,operation_id,operation_type,adapter_id,executor_id,target_id,input_digest,artifact_digest,idempotent,status,effect_state,started_at) VALUES('uncertain-step','uncertain-run',1,?,'host.action.execute','host-action-ssh','executor',?,?,?,1,'interrupted','effect-unknown','now')`, mutation.Operations[0].OperationID, input.HostID, mutation.Operations[0].InputDigest, mutation.Operations[0].ArtifactDigest)
	f.exec(`UPDATE system_meta SET state_revision=102 WHERE id=1`)
	if got := check("blocked"); got.ReasonCode != "host-binding-changed" {
		t.Fatalf("uncertain mutation retained admission: %+v", got)
	}
	f.exec(`UPDATE system_meta SET recovery_epoch=1 WHERE id=1`)
	check("unknown")

}

func admissionCanonicalPlan(p generated.Plan) generated.Plan {
	p.Binding.ToolVersion = "1.0.0"
	p.PlanID, p.PlanDigest = "", ""
	p.ReadableDigest = hostaction.BytesDigest([]byte("synthetic test plan"))
	d := hostaction.Digest(p)
	p.PlanDigest = d
	p.PlanID = "plan-" + d[7:39]
	return p
}

func (f admissionSQL) host(in generated.DebianAccessInput, host, identityDigest string) {
	draft := admissionTargetDraft(in, host)
	d := hostaction.Digest(draft)
	p := admissionCanonicalPlan(generated.Plan{DeclarationID: "registration-" + host, Binding: generated.PlanBinding{StateRevision: 1, DeclarationRevision: 1}, Operations: []generated.PlanOperation{{Sequence: 1, OperationID: "register", OperationType: "host.adopt", AdapterID: "core.host-adoption", TargetID: host, InputDigest: d, ArtifactDigest: d}}})
	f.plan(p)
	f.exec(`INSERT INTO host_discovery_drafts VALUES(?,?,1,0,'activate',?,?,'human-a',0,0)`, draft.Target.TargetID, draft.Target.TargetID, d, f.bytes(draft))
	f.exec(`INSERT INTO host_discovery_targets VALUES(?,1,?,'active',?,0)`, draft.Target.TargetID, draft.Target.TargetID, p.PlanID)
	obs := "observation-" + host
	f.exec(`INSERT INTO host_discovery_attempts VALUES(?,'human-a',?,?,?,1,?,1,0,0,'later',?)`, obs, d, d, draft.Target.TargetID, d, []byte(`{}`))
	f.exec(`INSERT INTO host_observations VALUES(?,?,1,?,?,0,0)`, obs, draft.Target.TargetID, []byte(`{}`), d)
	f.exec(`INSERT INTO host_adoption_drafts VALUES(?, ?,?,'human-a',1,0)`, "adoption-"+host, d, []byte(`{}`))
	f.exec(`INSERT INTO acknowledgement_requests VALUES(?,?,?,?,?,'human-a','fixture-authority',?,1,0,'later','approved',?,?,'now','now','now')`, "ack-"+host, p.PlanID, p.PlanDigest, d, d, d, []byte(`{}`), []byte(`{}`))
	f.exec(`INSERT INTO managed_hosts VALUES(?,?,?,'product-serial','qualified-virtual',?,?,?,?,'human-a',?,1,0)`, host, draft.Target.TargetID, identityDigest, obs, in.ProfileID, "adoption-"+host, p.PlanID, "ack-"+host)
}

func (f admissionSQL) measurement(x store.HostAdmissionMeasurement, id string, at time.Time, status string) {
	p := admissionCanonicalPlan(x.Plan)
	m := x.Measurement
	m.ObservedAt = at.Format(time.RFC3339)
	m.Status = status
	m.MeasurementDigest = hostaction.MeasurementDigest(m)
	result := x.Result
	result.ControlMeasurements = []generated.AccessMeasurement{m}
	result.ResultDigest = hostaction.ResultDigest(result)
	r := x.Receipt
	r.PlanID = p.PlanID
	r.PlanDigest = p.PlanDigest
	r.RunID = "run-" + id
	r.StepID = "step-" + id
	r.LeaseID = "lease-" + id
	r.ReceiptID = "receipt-" + id
	r.ResultDigest = result.ResultDigest
	r.RecordedAt = at.Format(time.RFC3339)
	f.receipt(p, r)
	c := x.Control
	c.ObservedAt = m.ObservedAt
	c.Status = status
	c.MeasurementDigest = m.MeasurementDigest
	c.ActionReceiptDigest = hostaction.Digest(r)
	f.exec(`INSERT INTO host_control_results VALUES(?,?,?,0,?,?,?,?,?,?,?,0,?,?,?,?,?,?,?,?,?)`, r.RunID, r.StepID, result.ResultDigest, p.PlanID, p.PlanDigest, hostaction.Digest(p.HostAccessSequence), r.OperationID, r.TargetID, c.HostID, c.IdentityDigest, r.ReceiptID, c.ActionReceiptDigest, c.ControlID, c.Status, c.ObservedAt, c.MeasurementDigest, f.bytes(m), f.bytes(c), f.bytes(result))
}

func (f admissionSQL) evidence(e generated.GateEvidence, b generated.GateEvidenceBundle) {
	e.BundleDigest = hostaction.Digest(b)
	typ := "gate.evidence.apply"
	if e.Status == "revoked" {
		typ = "gate.evidence.revoke"
	}
	op := generated.PlanOperation{Sequence: 1, OperationID: "apply-evidence", OperationType: typ, AdapterID: "core.gate", TargetID: e.SubjectID, InputDigest: e.BundleDigest, ArtifactDigest: e.BundleDigest}
	p := admissionCanonicalPlan(generated.Plan{DeclarationID: e.DeclarationID, Binding: generated.PlanBinding{StateRevision: e.StateRevision, DeclarationRevision: 1}, Operations: []generated.PlanOperation{op}})
	d := hostaction.Digest(e.EvidenceID)
	r := generated.ExecutionReceipt{Schema: generated.SchemaIDExecutionReceipt, SchemaVersion: "1.0.0", ReceiptID: "receipt-" + e.EvidenceID, LeaseID: "lease-" + e.EvidenceID, RunID: "run-" + e.EvidenceID, StepID: "step-" + e.EvidenceID, PlanID: p.PlanID, PlanDigest: p.PlanDigest, OperationID: op.OperationID, ExecutorID: "executor-central", AdapterID: "core.gate", TargetID: e.SubjectID, ArtifactDigest: e.BundleDigest, BindingDigest: d, NonceDigest: d, Status: "succeeded", ResultDigest: d, RecordedAt: e.AppliedAt, Extensions: []generated.ContractExtension{}}
	f.receipt(p, r)
	f.exec(`INSERT INTO acknowledgement_requests VALUES(?,?,?,?,?,'human-a','fixture-authority',?,?,0,'later','approved',?,?,'now','now','now')`, "ack-"+e.EvidenceID, p.PlanID, p.PlanDigest, d, d, d, e.StateRevision, []byte(`{}`), []byte(`{}`))
	f.exec(`UPDATE plan_runs SET acknowledgement_id=? WHERE run_id=?`, "ack-"+e.EvidenceID, r.RunID)
	f.exec(`INSERT INTO gate_evidence_drafts VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,'human-a',?)`, "draft-"+e.EvidenceID, e.EvidenceID, e.GateID, e.SubjectID, e.DefinitionVersion, e.EvaluatorVersion, e.SourceKind, e.ProofClass, e.SupersedesEvidenceID, e.RevokesEvidenceID, e.ArtifactDigest, e.BundleDigest, f.bytes(b), e.ObservedAt, e.StateRevision, e.AppliedAt)
	f.exec(`INSERT INTO gate_applied_evidence VALUES(?,?,?,?,?,?,?,?,?,?,0,?,1,?,?,?,?,?,?,?,?)`, e.EvidenceID, "draft-"+e.EvidenceID, e.GateID, e.SubjectID, e.Status, e.SourceKind, e.ProofClass, e.BundleDigest, f.bytes(e), e.StateRevision, p.DeclarationID, p.PlanID, p.PlanDigest, r.RunID, r.StepID, r.LeaseID, e.SupersedesEvidenceID, e.RevokesEvidenceID, e.AppliedAt)
}

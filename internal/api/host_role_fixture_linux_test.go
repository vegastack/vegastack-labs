//go:build linux

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/store"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Canonical synthetic producer rows are shared by API admission and role
// integration tests. This helper is test-only and grants no native provenance.
type roleAdmissionFixture struct {
	authority *store.Store
	db        *sql.DB
	seed      admissionSQL
	repo      *store.GateRepository
	ctx       context.Context
	snapshot  store.HostAdmissionSnapshot
	input     generated.DebianAccessInput
	expected  store.HostAdmissionSnapshot
	proofs    admissionSyntheticProvenance
}

func newRoleAdmissionFixture(t *testing.T, clock *time.Time) roleAdmissionFixture {
	t.Helper()
	expected := qualifiedHostSnapshot(t, (*clock))
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "control.db")
	authority, err := store.Open(context.Background(), store.Config{DatabasePath: path, Mode: store.InitializeNew, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "1.0.0", BuildVersion: "build-a", Clock: func() time.Time { return (*clock) }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = authority.Close() })
	db, err := sql.Open("sqlite3", "file:"+path+"?mode=rw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	f := admissionSQL{t, db}
	f.exec(`UPDATE system_meta SET state_revision=100 WHERE id=1`)
	f.exec(`INSERT INTO effective_authorization_principals VALUES('human-a','human','active',1,'now','now')`)
	var input generated.DebianAccessInput
	json.Unmarshal([]byte(expected.Measurements[0].Plan.HostAccessSequence.Actions[0].ActionInput), &input)
	for _, host := range []string{input.HostID, "source-host"} {
		id := input.HostIdentityDigest
		if host != input.HostID {
			id = hostaction.Digest(host)
		}
		f.host(input, host, id)
		f.exec(`INSERT INTO effective_authorization_grants VALUES(?,'human-a','reader','read','host.read','host',?,NULL,1,'active','now','now')`, "read-"+host, host)
	}

	// Persist one result and receipt per actual operation, preserving bounded
	// multi-measurement output and distinct execution leases.
	groups := map[string][]store.HostAdmissionMeasurement{}
	keys := []string{}
	for _, x := range expected.Measurements {
		key := x.Plan.PlanID + "-" + x.Receipt.OperationID
		if _, ok := groups[key]; !ok {
			keys = append(keys, key)
		}
		groups[key] = append(groups[key], x)
	}
	for _, key := range keys {
		group := groups[key]
		x := group[0]
		x.Plan = admissionCanonicalPlan(x.Plan)
		r := x.Result
		r.ControlMeasurements = []generated.AccessMeasurement{}
		for _, item := range group {
			r.ControlMeasurements = append(r.ControlMeasurements, item.Measurement)
		}
		r.ResultDigest = hostaction.ResultDigest(r)
		receipt := x.Receipt
		receipt.PlanID, receipt.PlanDigest = x.Plan.PlanID, x.Plan.PlanDigest
		receipt.RunID = "run-" + x.Plan.PlanID
		receipt.StepID = "step-" + key
		receipt.LeaseID = "lease-" + key
		receipt.ReceiptID = "receipt-" + key
		receipt.ResultDigest = r.ResultDigest
		f.receipt(x.Plan, receipt)
		for i, item := range group {
			c := item.Control
			c.ActionReceiptDigest = hostaction.Digest(receipt)
			f.exec(`INSERT INTO host_control_results VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, receipt.RunID, receipt.StepID, r.ResultDigest, i, x.Plan.PlanID, x.Plan.PlanDigest, hostaction.Digest(x.Plan.HostAccessSequence), receipt.OperationID, receipt.TargetID, c.HostID, c.IdentityDigest, c.RecoveryEpoch, receipt.ReceiptID, c.ActionReceiptDigest, c.ControlID, c.Status, c.ObservedAt, c.MeasurementDigest, f.bytes(item.Measurement), f.bytes(c), f.bytes(r))
		}
	}
	// A normal standalone recollection returns all three access observations
	// together. Its own plan has no sequence; the prior exact confirmation
	// must still select the existing finite probe records.
	for _, group := range groups {
		if group[0].Control.ControlID != "debian.accounts" {
			continue
		}
		x := group[0]
		request := x.Plan.HostAccessSequence.Actions[1]
		op := x.Plan.Operations[1]
		p := x.Plan
		p.HostAccessSequence = nil
		p.HostAction = &request
		p.Operations = []generated.PlanOperation{op}
		p = admissionCanonicalPlan(p)
		result := x.Result
		result.ControlMeasurements = nil
		for _, item := range group {
			result.ControlMeasurements = append(result.ControlMeasurements, item.Measurement)
		}
		result.ResultDigest = hostaction.ResultDigest(result)
		receipt := x.Receipt
		receipt.PlanID, receipt.PlanDigest = p.PlanID, p.PlanDigest
		receipt.RunID, receipt.StepID, receipt.LeaseID, receipt.ReceiptID = "run-recollect", "step-recollect", "lease-recollect", "receipt-recollect"
		receipt.ResultDigest = result.ResultDigest
		f.receipt(p, receipt)
		for i, item := range group {
			c := item.Control
			c.ActionReceiptDigest = hostaction.Digest(receipt)
			f.exec(`INSERT INTO host_control_results VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, receipt.RunID, receipt.StepID, result.ResultDigest, i, p.PlanID, p.PlanDigest, hostaction.Digest(p.HostAccessSequence), receipt.OperationID, receipt.TargetID, c.HostID, c.IdentityDigest, c.RecoveryEpoch, receipt.ReceiptID, c.ActionReceiptDigest, c.ControlID, c.Status, c.ObservedAt, c.MeasurementDigest, f.bytes(item.Measurement), f.bytes(c), f.bytes(result))
		}
	}
	proofs := admissionSyntheticProvenance{proofs: map[string]store.HostEvidenceProvenance{}}
	repo := store.NewGateRepositoryWithHostProvenance(authority, proofs)
	ctx := identity.WithVerifiedPrincipal(context.Background(), identity.Principal{ID: "human-a", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman})
	snapshot, err := repo.ResolveHostAdmission(ctx, input.HostID)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Blockers) != 0 {
		t.Fatalf("producer fixture blocked: %v", snapshot.Blockers)
	}
	for _, e := range expected.Evidence {
		e.StateRevision += 70
		b := expected.Bundles[e.EvidenceID]
		for i := range b.Facts {
			if b.Facts[i].FactID == "host.binding" {
				b.Facts[i].ValueDigest = snapshot.BindingDigest
			}
		}
		e.BundleDigest = hostaction.Digest(b)
		e.ArtifactDigest = snapshot.BindingDigest
		op := generated.PlanOperation{Sequence: 1, OperationID: "apply-evidence", OperationType: "gate.evidence.apply", AdapterID: "core.gate", TargetID: input.HostID, InputDigest: e.BundleDigest, ArtifactDigest: e.BundleDigest}
		p := generated.Plan{PlanID: "plan-" + e.EvidenceID, PlanDigest: hostaction.Digest("plan-" + e.EvidenceID), DeclarationID: e.DeclarationID, Binding: generated.PlanBinding{StateRevision: e.StateRevision, DeclarationRevision: 1}, Operations: []generated.PlanOperation{op}}
		p = admissionCanonicalPlan(p)
		d := hostaction.Digest(e.EvidenceID)
		r := generated.ExecutionReceipt{Schema: generated.SchemaIDExecutionReceipt, SchemaVersion: "1.0.0", ReceiptID: "receipt-" + e.EvidenceID, LeaseID: "lease-" + e.EvidenceID, RunID: "run-" + e.EvidenceID, StepID: "step-" + e.EvidenceID, PlanID: p.PlanID, PlanDigest: p.PlanDigest, OperationID: op.OperationID, ExecutorID: "executor-central", AdapterID: "core.gate", TargetID: input.HostID, ArtifactDigest: e.BundleDigest, BindingDigest: d, NonceDigest: d, Status: "succeeded", ResultDigest: d, RecordedAt: (*clock).Format(time.RFC3339), Extensions: []generated.ContractExtension{}}
		f.receipt(p, r)
		f.exec(`INSERT INTO gate_evidence_drafts VALUES(?,?,?,?,?,?,?,?,NULL,NULL,?,?,?,?,?,0,'human-a',?)`, "draft-"+e.EvidenceID, e.EvidenceID, e.GateID, e.SubjectID, e.DefinitionVersion, e.EvaluatorVersion, e.SourceKind, e.ProofClass, e.ArtifactDigest, e.BundleDigest, f.bytes(b), e.ObservedAt, e.StateRevision, e.AppliedAt)
		f.exec(`INSERT INTO gate_applied_evidence VALUES(?,?,?,?,'applied',?,?,?,?,?,0,?,1,?,?,?,?,?,NULL,NULL,?)`, e.EvidenceID, "draft-"+e.EvidenceID, e.GateID, e.SubjectID, e.SourceKind, e.ProofClass, e.BundleDigest, f.bytes(e), e.StateRevision, p.DeclarationID, p.PlanID, p.PlanDigest, r.RunID, r.StepID, r.LeaseID, e.AppliedAt)
		if strings.HasPrefix(e.EvidenceID, "prereq-") {
			key := strings.TrimPrefix(e.EvidenceID, "prereq-")
			proofs.proofs[e.EvidenceID] = store.HostEvidenceProvenance{PrerequisiteID: key, PrerequisiteDigest: expected.PrerequisiteDigests[key]}
		}
		if e.EvidenceID == "native-baseline" {
			q := expected.Qualifications[0]
			proofs.proofs[e.EvidenceID] = store.HostEvidenceProvenance{Qualification: &q}
		}
	}
	f.exec(`INSERT INTO gate_applied_profiles(binding_id,profile_id,profile_version,policy_id,policy_version,capabilities_bytes,state_revision,recovery_epoch,declaration_id,declaration_revision,plan_id,plan_digest,run_id,step_id,lease_id,human_id,applied_at) VALUES('scope-a','vegastack-labs','1.0.0','policy-a','1.0.0',X'5B5D',1,0,'scope-declaration',1,'scope-plan',?,'scope-run','scope-step','scope-lease','human-a',?)`, hostaction.Digest("scope"), (*clock).Format(time.RFC3339))

	return roleAdmissionFixture{authority, db, f, repo, ctx, snapshot, input, expected, proofs}
}

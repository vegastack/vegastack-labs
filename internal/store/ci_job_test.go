package store

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"strings"
	"testing"
)

func ciJobBindingFixture() generated.CiJobExecutionBinding {
	d := hostaction.Digest("runtime")
	return generated.CiJobExecutionBinding{Schema: generated.SchemaIDCiJobExecutionBinding, SchemaVersion: "1.0.0", BindingID: "ci-runtime", HostID: "host-a", HostIdentityDigest: d, TargetRevision: 1, TargetDigest: d, AutomationPrincipalID: "automation-a", CallerUID: 1001, SSHReferenceID: "ssh-a", SSHMaterialVersion: "v1", RegistrationReferenceID: "registration-a", RegistrationMaterialVersion: "v1", ObserverReferenceID: "observer-a", ObserverMaterialVersion: "v1", RuntimeProfileID: "runtime-a", RuntimeDigest: d, RunnerGroupName: "isolated", MaximumSeconds: 60}
}
func TestCIJobExactManifestAndDeclaration(t *testing.T) {
	b := ciJobBindingFixture()
	r := NewCIJobRepository(&Store{config: Config{CIJobBindings: []generated.CiJobExecutionBinding{b}}})
	in := generated.CiJobRequest{Schema: generated.SchemaIDCiJobRequest, SchemaVersion: "1.0.0", Definition: ciEnrollmentPolicyFixture().Definition, ExecutionBindingID: b.BindingID, ExecutionBindingDigest: hostaction.Digest(b), HostID: b.HostID, HostIdentityDigest: b.HostIdentityDigest, HostAdmissionDigest: hostaction.Digest("admission"), RunID: "60", Attempt: 2, ExpectedStateRevision: 7, IdempotencyKey: "job-a", ReasonDigest: hostaction.Digest("reason")}
	bindings, e := r.StepBindings(in)
	if e != nil || len(bindings) != 3 {
		t.Fatal(bindings, e)
	}
	purposes := map[string]bool{}
	for _, v := range bindings {
		if !credentialref.ValidBinding(v) || v.StateRevision != 10 || v.TargetID != b.HostID || v.ConsumerID != "host-action" {
			t.Fatal(v)
		}
		purposes[v.PurposeID] = true
	}
	if len(purposes) != 3 {
		t.Fatal("purpose mixing")
	}
	d := generated.DeclarationRevision{Schema: generated.SchemaIDDeclarationRevision, SchemaVersion: "1.0.0", CIJob: &in, DeclarationID: ciJobID(in), DeclarationType: CIJobOperation, Revision: 1, StateRevision: 8, Status: "draft", Extensions: []generated.ContractExtension{{Name: "x-credential-bindings", ValueDigest: credentialref.ManifestDigest(bindings)}}, Operations: []generated.DeclarationOperation{{Sequence: 1, OperationID: "ci-job", OperationType: CIJobOperation, AdapterID: "host-action", TargetID: b.HostID, InputDigest: credentialref.OperationManifestDigest(bindings, "ci-job"), ArtifactDigest: hostaction.Digest(in)}}}
	if !ValidateCIJobDeclaration(d) {
		t.Fatal("exact draft rejected")
	}
	if d.Operations[0].InputDigest == d.Operations[0].ArtifactDigest {
		t.Fatal("credential manifest lost")
	}
	for _, edit := range []func(*generated.DeclarationRevision){func(d *generated.DeclarationRevision) { d.Operations[0].TargetID = "other" }, func(d *generated.DeclarationRevision) { d.Operations[0].Idempotent = true }, func(d *generated.DeclarationRevision) { d.CIEnrollment = &generated.CiEnrollmentRequest{} }, func(d *generated.DeclarationRevision) { d.Extensions = nil }, func(d *generated.DeclarationRevision) { d.CIJob.RunID = "060" }, func(d *generated.DeclarationRevision) { d.CIJob.Attempt = 1 << 32 }} {
		copy := d
		req := in
		copy.CIJob = &req
		copy.Operations = append([]generated.DeclarationOperation(nil), d.Operations...)
		edit(&copy)
		if ValidateCIJobDeclaration(copy) {
			t.Fatal("changed draft accepted")
		}
	}
	if strings.Contains(string(mustCIEnrollmentBytes(in)), "private-owner") {
		t.Fatal("private source policy exported")
	}
}
func TestCIJobMissingAuthorityNeverExecutes(t *testing.T) {
	r := NewCIJobRepository(nil)
	if _, e := r.CurrentExecution(context.Background(), adapter.Operation{}, adapter.ExactExecutionBinding{}); e == nil {
		t.Fatal("nil authority accepted")
	}
	if e := r.ValidatePlan(context.Background(), generated.Plan{}); e == nil {
		t.Fatal("missing host gates accepted")
	}
	if _, e := r.Prepare(context.Background(), generated.CiJobDraftRequest{}); e == nil {
		t.Fatal("empty draft accepted")
	}
}
func TestCIJobLifecycleBindsExactExistingLease(t *testing.T) {
	b := adapter.ExactExecutionBinding{PlanID: "plan-a", RunID: "run-a", StepID: "step-a", LeaseID: "lease-a"}
	first := CIJobLifecycleID(b)
	b.LeaseID = "lease-b"
	if first == CIJobLifecycleID(b) || CIJobRunnerName(b) == "" {
		t.Fatal("replayable lifecycle")
	}
}

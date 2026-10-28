package store

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"testing"
)

func TestCIPublicationSealKeepsCompletedSourceIndependentOfOldLease(t *testing.T) {
	b := generated.CiPublicationBinding{BindingID: "publication", SourceRunID: "run-source", SourceStepID: "step-source"}
	source := CIPublicationSource{RunID: "60", JobID: "70", Attempt: 2, CompletionDigest: hostaction.Digest("completion"), Observer: credentialref.StepBinding{ReferenceID: "observer-a", StateRevision: 4}}
	d := CIPublicationDigest(b, source)
	source.Observer.StateRevision = 20
	if CIPublicationDigest(b, source) != d {
		t.Fatal("later publication revision invalidated immutable source")
	}
	source.JobID = "71"
	if CIPublicationDigest(b, source) == d {
		t.Fatal("numeric source changed without seal")
	}
	bindings := CIPublicationBindings(b, 20, 2)
	if len(bindings) != 1 || bindings[0].ConsumerID != CIPublicationAdapter || bindings[0].PurposeID != CIPublicationPurpose || bindings[0].StateRevision != 20 || bindings[0].RecoveryEpoch != 2 {
		t.Fatal("publication credential mixed", bindings)
	}
}
func TestCIPublicationDeclarationDeniesSiblingAndWrongSeals(t *testing.T) {
	digest := hostaction.Digest("artifact")
	manifest := hostaction.Digest("manifest")
	d := generated.DeclarationRevision{DeclarationType: CIPublicationOperation, Operations: []generated.DeclarationOperation{{Sequence: 1, OperationID: "ci-publication", OperationType: CIPublicationOperation, AdapterID: CIPublicationAdapter, TargetID: "publication", InputDigest: manifest, ArtifactDigest: digest}}, Extensions: []generated.ContractExtension{{Name: CIPublicationExtension, ValueDigest: digest}, {Name: "x-credential-bindings", ValueDigest: manifest}}}
	if !ValidCIPublicationDeclaration(d) {
		t.Fatal("exact draft rejected")
	}
	for _, change := range []func(*generated.DeclarationRevision){func(d *generated.DeclarationRevision) { d.Operations[0].Idempotent = true }, func(d *generated.DeclarationRevision) { d.Operations[0].Sequence = 2 }, func(d *generated.DeclarationRevision) { d.Operations[0].AdapterID = "hosting.coolify" }, func(d *generated.DeclarationRevision) { d.Extensions[0].ValueDigest = manifest }, func(d *generated.DeclarationRevision) { d.Operations = append(d.Operations, d.Operations[0]) }, func(d *generated.DeclarationRevision) { d.CIEnrollment = &generated.CiEnrollmentRequest{} }, func(d *generated.DeclarationRevision) { d.Extensions = append(d.Extensions, d.Extensions[0]) }} {
		copy := d
		copy.Operations = append([]generated.DeclarationOperation(nil), d.Operations...)
		copy.Extensions = append([]generated.ContractExtension(nil), d.Extensions...)
		change(&copy)
		if ValidCIPublicationDeclaration(copy) {
			t.Fatal("altered publication draft accepted")
		}
	}
}
func TestCIPublicationMissingAuthorityFailsClosed(t *testing.T) {
	r := NewCIPublicationRepository(nil)
	if _, e := r.Current(context.Background(), adapter.Operation{}, adapter.ExactExecutionBinding{}); e == nil {
		t.Fatal("missing authority accepted")
	}
	if _, _, e := r.Draft(context.Background(), generated.CiPublicationDraftRequest{}); e == nil {
		t.Fatal("missing source accepted")
	}
}

func TestCIPublicationAttemptIsOneUseAcrossRuns(t *testing.T) {
	a := adapter.ExactExecutionBinding{PlanID: "plan-a", RunID: "run-a", StepID: "step-a", LeaseID: "lease-a"}
	b := a
	b.RunID = "run-b"
	b.StepID = "step-b"
	b.LeaseID = "lease-b"
	if ciPublicationIntentKey(a, "attempted") != ciPublicationIntentKey(b, "attempted") {
		t.Fatal("new run could replay exact immutable publication plan")
	}
	b.PlanID = "plan-b"
	if ciPublicationIntentKey(a, "attempted") == ciPublicationIntentKey(b, "attempted") {
		t.Fatal("distinct new plan lost independent approval boundary")
	}
}

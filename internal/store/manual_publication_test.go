package store

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"testing"
)

func TestManualPublicationDeclarationDeniesSiblingAndWrongSeals(t *testing.T) {
	digest := hostaction.Digest("artifact")
	manifest := hostaction.Digest("manifest")
	d := generated.DeclarationRevision{DeclarationType: ManualPublicationOperation, Operations: []generated.DeclarationOperation{{Sequence: 1, OperationID: "manual-publication", OperationType: ManualPublicationOperation, AdapterID: ManualPublicationAdapter, TargetID: "publication", InputDigest: manifest, ArtifactDigest: digest}}, Extensions: []generated.ContractExtension{{Name: ManualPublicationExtension, ValueDigest: digest}, {Name: "x-credential-bindings", ValueDigest: manifest}}}
	if !ValidManualPublicationDeclaration(d) {
		t.Fatal("exact draft rejected")
	}
	for _, change := range []func(*generated.DeclarationRevision){func(d *generated.DeclarationRevision) { d.Operations[0].Idempotent = true }, func(d *generated.DeclarationRevision) { d.Operations[0].Sequence = 2 }, func(d *generated.DeclarationRevision) { d.Operations[0].AdapterID = "hosting.coolify" }, func(d *generated.DeclarationRevision) { d.Extensions[0].ValueDigest = manifest }, func(d *generated.DeclarationRevision) { d.Operations = append(d.Operations, d.Operations[0]) }, func(d *generated.DeclarationRevision) { d.CIEnrollment = &generated.CiEnrollmentRequest{} }, func(d *generated.DeclarationRevision) { d.Extensions = append(d.Extensions, d.Extensions[0]) }} {
		copy := d
		copy.Operations = append([]generated.DeclarationOperation(nil), d.Operations...)
		copy.Extensions = append([]generated.ContractExtension(nil), d.Extensions...)
		change(&copy)
		if ValidManualPublicationDeclaration(copy) {
			t.Fatal("altered publication draft accepted")
		}
	}
}
func TestManualPublicationMissingAuthorityFailsClosed(t *testing.T) {
	r := NewManualPublicationRepository(nil)
	if _, e := r.Current(context.Background(), adapter.Operation{}, adapter.ExactExecutionBinding{}); e == nil {
		t.Fatal("missing authority accepted")
	}
	if _, _, e := r.Draft(context.Background(), generated.ManualPublicationDraftRequest{}); e == nil {
		t.Fatal("missing source accepted")
	}
}

func TestManualPublicationAttemptIsOneUseAcrossRuns(t *testing.T) {
	a := adapter.ExactExecutionBinding{PlanID: "plan-a", RunID: "run-a", StepID: "step-a", LeaseID: "lease-a"}
	b := a
	b.RunID = "run-b"
	b.StepID = "step-b"
	b.LeaseID = "lease-b"
	if manualPublicationIntentKey(a, "attempted") != manualPublicationIntentKey(b, "attempted") {
		t.Fatal("new run could replay exact immutable publication plan")
	}
	b.PlanID = "plan-b"
	if manualPublicationIntentKey(a, "attempted") == manualPublicationIntentKey(b, "attempted") {
		t.Fatal("distinct new plan lost independent approval boundary")
	}
}

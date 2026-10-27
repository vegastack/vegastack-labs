package store

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"strings"
	"testing"
)

func ciEnrollmentPolicyFixture() CIEnrollmentPolicy {
	b := generated.CiEnrollmentBinding{Schema: generated.SchemaIDCiEnrollmentBinding, SchemaVersion: "1.0.0", EnrollmentID: "enrollment-a", OwnerID: "human-a", BindingID: "binding-a", AdapterID: "scm.github", RepositoryID: "101", RepositoryOwnerID: "202", Repository: "private-owner/private-repo", WorkflowID: "303", WorkflowPath: ".github/workflows/private.yml", WorkflowDigest: "sha256:" + strings.Repeat("a", 64), Revision: strings.Repeat("b", 40), Ref: "refs/heads/main", Event: "push", JobName: "private-job", RunnerGroupID: "404", Labels: []string{"isolated", "linux"}}
	return CIEnrollmentPolicy{Definition: generated.CiEnrollmentDefinition{Schema: generated.SchemaIDCiEnrollmentDefinition, SchemaVersion: "1.0.0", EnrollmentID: b.EnrollmentID, OwnerID: b.OwnerID, BindingID: b.BindingID, BindingDigest: ciEnrollmentDigest(b)}, Binding: b, ResourceKeyDigest: CIEnrollmentPolicyKey(b)}
}
func TestCIEnrollmentPolicyFreezeAndExactDefinition(t *testing.T) {
	p := ciEnrollmentPolicyFixture()
	in := []CIEnrollmentPolicy{p}
	c, err := normalizeConfig(Config{ToolVersion: "test", BuildVersion: "test", CIEnrollmentPolicies: in})
	if err != nil {
		t.Fatal(err)
	}
	in[0].Binding.Labels[0] = "mutated"
	if c.CIEnrollmentPolicies[0].Binding.Labels[0] != "isolated" {
		t.Fatal("mutable config escaped")
	}
	for _, mutate := range []func(*CIEnrollmentPolicy){func(p *CIEnrollmentPolicy) { p.Definition.BindingDigest = ciEnrollmentDigest("wrong") }, func(p *CIEnrollmentPolicy) { p.ResourceKeyDigest = ciEnrollmentDigest("wrong") }, func(p *CIEnrollmentPolicy) { p.Definition.OwnerID = "another-human" }, func(p *CIEnrollmentPolicy) { p.Definition.Schema = "wrong" }} {
		p = ciEnrollmentPolicyFixture()
		mutate(&p)
		if _, err := normalizeConfig(Config{ToolVersion: "test", BuildVersion: "test", CIEnrollmentPolicies: []CIEnrollmentPolicy{p}}); err == nil {
			t.Fatal("mismatched config accepted")
		}
	}
}
func TestCIEnrollmentDeclarationBindsOnlyExactPolicyDigest(t *testing.T) {
	p := ciEnrollmentPolicyFixture()
	in := generated.CiEnrollmentRequest{Schema: generated.SchemaIDCiEnrollmentRequest, SchemaVersion: "1.0.0", Definition: p.Definition, ReasonDigest: ciEnrollmentDigest("reason"), IdempotencyKey: "request-a"}
	digest := ciEnrollmentDigest(in)
	d := generated.DeclarationRevision{CIEnrollment: &in, DeclarationID: ciEnrollmentDeclarationID(in.Definition.EnrollmentID), DeclarationType: ciEnrollmentOperation, Revision: 1, StateRevision: 1, Status: "draft", Operations: []generated.DeclarationOperation{{Sequence: 1, OperationID: ciEnrollmentOperationID, OperationType: ciEnrollmentOperation, AdapterID: ciEnrollmentAdapterID, TargetID: in.Definition.EnrollmentID, InputDigest: digest, ArtifactDigest: digest}}}
	if !ValidateCIEnrollmentDeclaration(d) {
		t.Fatal("valid exact declaration denied")
	}
	for _, mutate := range []func(*generated.DeclarationRevision){func(d *generated.DeclarationRevision) { d.Operations[0].TargetID = "another" }, func(d *generated.DeclarationRevision) { d.Operations[0].Idempotent = true }, func(d *generated.DeclarationRevision) { d.ServiceImport = &generated.ServiceImportRequest{} }, func(d *generated.DeclarationRevision) { d.RecoveryEpoch = 1 }, func(d *generated.DeclarationRevision) {
		d.CIEnrollment.Definition.BindingDigest = ciEnrollmentDigest("wrong")
	}} {
		clone := d
		inClone := in
		clone.CIEnrollment = &inClone
		clone.Operations = append([]generated.DeclarationOperation(nil), d.Operations...)
		mutate(&clone)
		if ValidateCIEnrollmentDeclaration(clone) {
			t.Fatal("changed exact declaration accepted")
		}
	}
}

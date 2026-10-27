package serverconfig

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"strings"
	"testing"
)

func ciBindingFixture() generated.CiEnrollmentBinding {
	return generated.CiEnrollmentBinding{Schema: generated.SchemaIDCiEnrollmentBinding, SchemaVersion: "1.0.0", EnrollmentID: "enrollment-a", OwnerID: "human-a", BindingID: "binding-a", AdapterID: "scm.github", RepositoryID: "101", RepositoryOwnerID: "202", Repository: "owner/repo", WorkflowID: "303", WorkflowPath: ".github/workflows/build.yml", WorkflowDigest: "sha256:" + strings.Repeat("a", 64), Revision: strings.Repeat("b", 40), Ref: "refs/heads/main", Event: "push", JobName: "build", RunnerGroupID: "404", Labels: []string{"linux", "isolated"}}
}
func TestCIEnrollmentBindingsFreezeOwnsLabelsAndRejectsAmbiguity(t *testing.T) {
	b := ciBindingFixture()
	input := []generated.CiEnrollmentBinding{b}
	frozen, err := FreezeCIEnrollmentBindings(input)
	if err != nil {
		t.Fatal(err)
	}
	input[0].Labels[0] = "mutated"
	if frozen[0].Labels[0] != "isolated" || frozen[0].Labels[1] != "linux" {
		t.Fatal("labels not privately frozen", frozen)
	}
	for _, change := range []func(*generated.CiEnrollmentBinding){
		func(v *generated.CiEnrollmentBinding) { v.RepositoryOwnerID = "" }, func(v *generated.CiEnrollmentBinding) { v.Revision = "main" }, func(v *generated.CiEnrollmentBinding) { v.Event = "pull_request" }, func(v *generated.CiEnrollmentBinding) { v.Labels = []string{"linux", "linux"} }, func(v *generated.CiEnrollmentBinding) { v.AdapterID = "unknown" }, func(v *generated.CiEnrollmentBinding) { v.Ref = "refs/heads/*" }, func(v *generated.CiEnrollmentBinding) { v.WorkflowPath = "../private" },
	} {
		b = ciBindingFixture()
		change(&b)
		if _, err := FreezeCIEnrollmentBindings([]generated.CiEnrollmentBinding{b}); err == nil {
			t.Fatal("invalid policy accepted", b)
		}
	}
	b = ciBindingFixture()
	other := b
	other.EnrollmentID = "enrollment-b"
	other.BindingID = "binding-b"
	for _, input := range [][]generated.CiEnrollmentBinding{{b, b}, {b, other}, make([]generated.CiEnrollmentBinding, 129)} {
		if _, err := FreezeCIEnrollmentBindings(input); err == nil {
			t.Fatal("ambiguous policies accepted")
		}
	}
}

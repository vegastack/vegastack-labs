package server

import (
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"strings"
	"testing"
)

func TestCIEnrollmentCompositionBindsPrivatePolicyAndDistinctOwners(t *testing.T) {
	b := generated.CiEnrollmentBinding{Schema: generated.SchemaIDCiEnrollmentBinding, SchemaVersion: "1.0.0", EnrollmentID: "enrollment-a", OwnerID: "human-a", BindingID: "binding-a", AdapterID: "scm.github", RepositoryID: "101", RepositoryOwnerID: "202", Repository: "private-owner/private-repo", WorkflowID: "303", WorkflowPath: ".github/workflows/private.yml", WorkflowDigest: "sha256:" + strings.Repeat("a", 64), Revision: strings.Repeat("b", 40), Ref: "refs/heads/main", Event: "push", JobName: "private-job", RunnerGroupID: "404", Labels: []string{"isolated", "linux"}}
	p, err := ciEnrollmentPolicies([]generated.CiEnrollmentBinding{b})
	if err != nil || len(p) != 1 {
		t.Fatal(p, err)
	}
	if p[0].Definition.OwnerID != "human-a" || p[0].Binding.RepositoryOwnerID != "202" || p[0].Definition.BindingDigest != hostaction.Digest(p[0].Binding) {
		t.Fatal("lost exact binding", p)
	}
	raw, _ := json.Marshal(p[0].Definition)
	for _, private := range []string{b.Repository, b.WorkflowPath, b.JobName} {
		if strings.Contains(string(raw), private) {
			t.Fatal("private policy leaked into public definition")
		}
	}
	b.Labels[0] = "mutated"
	if p[0].Binding.Labels[0] != "isolated" {
		t.Fatal("protected profile labels were borrowed")
	}
	changed := p[0].Binding
	changed.Repository = "another/repository"
	other, err := ciEnrollmentPolicies([]generated.CiEnrollmentBinding{changed})
	if err != nil || other[0].Definition.BindingDigest == p[0].Definition.BindingDigest {
		t.Fatal("source change lost exact identity", err)
	}
}

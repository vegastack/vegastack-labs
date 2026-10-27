package serverconfig

import (
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/ci"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"slices"
)

func FreezeCIEnrollmentBindings(input []generated.CiEnrollmentBinding) ([]generated.CiEnrollmentBinding, error) {
	invalid := func() ([]generated.CiEnrollmentBinding, error) {
		return nil, failure.New(generated.ErrorCodeInputInvalid, "ci-enrollment", false)
	}
	if len(input) > 128 {
		return invalid()
	}
	out := make([]generated.CiEnrollmentBinding, 0, len(input))
	ids, bindings, policies := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, b := range input {
		raw, _ := json.Marshal(b)
		if generated.ValidateContractJSON(generated.SchemaIDCiEnrollmentBinding, raw, generated.ContractExact) != nil || b.AdapterID != "scm.github" {
			return invalid()
		}
		p := ci.PolicyBinding{RepositoryID: b.RepositoryID, OwnerID: b.RepositoryOwnerID, Repository: b.Repository, WorkflowID: b.WorkflowID, WorkflowPath: b.WorkflowPath, WorkflowDigest: b.WorkflowDigest, Revision: b.Revision, Ref: b.Ref, Event: b.Event, JobName: b.JobName, RunnerGroupID: b.RunnerGroupID, Labels: b.Labels}
		if ci.ValidatePolicyBinding(p) != nil {
			return invalid()
		}
		b.Labels = slices.Clone(b.Labels)
		slices.Sort(b.Labels)
		p.Labels = b.Labels
		key := hostaction.Digest(p)
		if ids[b.EnrollmentID] || bindings[b.BindingID] || policies[key] {
			return invalid()
		}
		ids[b.EnrollmentID] = true
		bindings[b.BindingID] = true
		policies[key] = true
		out = append(out, b)
	}
	return out, nil
}

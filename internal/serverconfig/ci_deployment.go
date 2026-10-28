package serverconfig

import (
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"strconv"
)

// CIDeploymentJobDigest omits the derived plan identity to avoid a circular
// digest. The plan seals this exact protected job in x-executor-deployment-job.
func CIDeploymentJobDigest(b generated.CiDeploymentJobBinding) string {
	b.PlanID = ""
	b.PlanDigest = ""
	return hostaction.Digest(b)
}
func FreezeCIDeploymentJobs(input []generated.CiDeploymentJobBinding, jobs []generated.CiJobExecutionBinding, enrollments []generated.CiEnrollmentBinding) ([]generated.CiDeploymentJobBinding, error) {
	invalid := func() ([]generated.CiDeploymentJobBinding, error) {
		return nil, failure.New(generated.ErrorCodeInputInvalid, "ci-deployment-job", false)
	}
	frozen, e := FreezeCIEnrollmentBindings(enrollments)
	if e != nil {
		return invalid()
	}
	enrollments = frozen
	if len(input) > 64 {
		return invalid()
	}
	out := append([]generated.CiDeploymentJobBinding(nil), input...)
	seen := map[string]bool{}
	for _, b := range out {
		raw, _ := json.Marshal(b)
		if generated.ValidateContractJSON(generated.SchemaIDCiDeploymentJobBinding, raw, generated.ContractExact) != nil || seen[b.PlanID] || b.Attempt > int64(^uint32(0)) {
			return invalid()
		}
		seen[b.PlanID] = true
		for _, id := range []string{b.RunID, b.JobID, b.RunnerID} {
			n, e := strconv.ParseInt(id, 10, 64)
			if e != nil || n <= 0 || strconv.FormatInt(n, 10) != id {
				return invalid()
			}
		}
		jobOK, enrollmentOK := false, false
		for _, j := range jobs {
			if j.BindingID == b.ExecutionBindingID && j.AutomationPrincipalID == b.ExecutorID && hostaction.Digest(j) == b.ExecutionBindingDigest {
				jobOK = true
			}
		}
		for _, e := range enrollments {
			if e.EnrollmentID == b.EnrollmentID && e.JobClass == "deployment" && hostaction.Digest(e) == b.EnrollmentDigest {
				enrollmentOK = true
			}
		}
		if !jobOK || !enrollmentOK {
			return invalid()
		}
	}
	return out, nil
}

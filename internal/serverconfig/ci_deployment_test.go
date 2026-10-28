package serverconfig

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"testing"
)

func TestCIDeploymentProfileRejectsBuildAndUnboundJobs(t *testing.T) {
	if out, e := FreezeCIDeploymentJobs(nil, nil, nil); e != nil || len(out) != 0 {
		t.Fatal(out, e)
	}
	b := generated.CiDeploymentJobBinding{Schema: generated.SchemaIDCiDeploymentJobBinding, SchemaVersion: "1.0.0", PlanID: "plan-a", PlanDigest: hostaction.Digest("plan"), ExecutionBindingID: "execution-a", ExecutionBindingDigest: hostaction.Digest("execution"), EnrollmentID: "enrollment-a", EnrollmentDigest: hostaction.Digest("enrollment"), ExecutorID: "executor-a", TargetID: "service-a", ArtifactDigest: hostaction.Digest("image"), RunID: "10", JobID: "11", RunnerID: "12", Attempt: 1}
	for _, inputs := range [][]generated.CiDeploymentJobBinding{{b}, {b, b}} {
		if _, e := FreezeCIDeploymentJobs(inputs, nil, nil); e == nil {
			t.Fatal("unbound policy accepted")
		}
	}
	digest := CIDeploymentJobDigest(b)
	b.PlanID = "another-derived-plan"
	b.PlanDigest = hostaction.Digest("derived")
	if CIDeploymentJobDigest(b) != digest {
		t.Fatal("digest circular on derived plan")
	}
	b.JobID = "99"
	if CIDeploymentJobDigest(b) == digest {
		t.Fatal("job identity omitted")
	}
}

func TestCIDeploymentProfileAllowsOnlyExactDeploymentEnrollment(t *testing.T) {
	enrollment := ciBindingFixture()
	enrollment.JobClass = "deployment"
	frozen, e := FreezeCIEnrollmentBindings([]generated.CiEnrollmentBinding{enrollment})
	if e != nil {
		t.Fatal(e)
	}
	job := ciJobBindingFixture()
	b := generated.CiDeploymentJobBinding{Schema: generated.SchemaIDCiDeploymentJobBinding, SchemaVersion: "1.0.0", PlanID: "plan-a", PlanDigest: hostaction.Digest("plan"), ExecutionBindingID: job.BindingID, ExecutionBindingDigest: hostaction.Digest(job), EnrollmentID: enrollment.EnrollmentID, EnrollmentDigest: hostaction.Digest(frozen[0]), ExecutorID: job.AutomationPrincipalID, TargetID: "service-a", ArtifactDigest: hostaction.Digest("image"), RunID: "10", JobID: "11", RunnerID: "12", Attempt: 1}
	if _, e := FreezeCIDeploymentJobs([]generated.CiDeploymentJobBinding{b}, []generated.CiJobExecutionBinding{job}, []generated.CiEnrollmentBinding{enrollment}); e != nil {
		t.Fatal(e)
	}
	enrollment.JobClass = "build"
	b.EnrollmentDigest = hostaction.Digest(enrollment)
	if _, e := FreezeCIDeploymentJobs([]generated.CiDeploymentJobBinding{b}, []generated.CiJobExecutionBinding{job}, []generated.CiEnrollmentBinding{enrollment}); e == nil {
		t.Fatal("build enrollment granted deployment")
	}
}

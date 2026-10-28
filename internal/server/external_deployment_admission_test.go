package server

import (
	"github.com/vegastack/vegastack-labs/internal/ci"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"strings"
	"testing"
	"time"
)

func externalDeploymentFixture() (generated.CiDeploymentJobBinding, generated.CiEnrollmentBinding, ci.Observation) {
	b := generated.CiEnrollmentBinding{Schema: generated.SchemaIDCiEnrollmentBinding, SchemaVersion: "1.0.0", JobClass: "deployment", EnrollmentID: "enrollment-a", OwnerID: "owner-a", BindingID: "binding-a", AdapterID: "scm.github", RepositoryID: "1", RepositoryOwnerID: "2", Repository: "team/app", WorkflowID: "3", WorkflowPath: ".github/workflows/deploy.yml", WorkflowDigest: hostaction.Digest("workflow"), Revision: strings.Repeat("a", 40), Ref: "refs/heads/main", Event: "workflow_dispatch", JobName: "deploy", RunnerGroupID: "4", Labels: []string{"private-deploy"}}
	selected := generated.CiDeploymentJobBinding{Schema: generated.SchemaIDCiDeploymentJobBinding, SchemaVersion: "1.0.0", PlanID: "plan-a", PlanDigest: hostaction.Digest("plan"), ExecutionBindingID: "execution-a", ExecutionBindingDigest: hostaction.Digest("execution"), EnrollmentID: b.EnrollmentID, EnrollmentDigest: hostaction.Digest(b), ExecutorID: "executor-a", TargetID: "service-a", ArtifactDigest: hostaction.Digest("image"), RunID: "10", JobID: "11", RunnerID: "12", Attempt: 1}
	o := ci.Observation{Binding: deploymentEnrollment(b, selected.RunnerID).Binding, HeadRepositoryID: b.RepositoryID, RunID: selected.RunID, JobID: selected.JobID, Attempt: 1, RunStatus: "in_progress", JobStatus: "in_progress", ObservedAt: time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)}
	return selected, b, o
}
func TestExternalDeploymentProtectedScopeAndObservation(t *testing.T) {
	selected, b, o := externalDeploymentFixture()
	now := o.ObservedAt
	if err := matchDeploymentObservation(selected, b, o, now); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"build", "wrong-run", "wrong-job", "attempt", "runner", "workflow", "source", "fork", "stale", "cancelled", "policy"} {
		t.Run(mode, func(t *testing.T) {
			s, b, o := externalDeploymentFixture()
			switch mode {
			case "build":
				b.JobClass = "build"
				s.EnrollmentDigest = hostaction.Digest(b)
			case "wrong-run":
				o.RunID = "99"
			case "wrong-job":
				o.JobID = "99"
			case "attempt":
				o.Attempt++
			case "runner":
				o.Binding.RunnerID = "99"
			case "workflow":
				o.Binding.WorkflowDigest = hostaction.Digest("wrong")
			case "source":
				o.Binding.Revision = strings.Repeat("b", 40)
			case "fork":
				o.HeadRepositoryID = "99"
			case "stale":
				o.ObservedAt = o.ObservedAt.Add(-61 * time.Second)
			case "cancelled":
				o.JobStatus = "completed"
			case "policy":
				b.Ref = "refs/heads/other"
			}
			if matchDeploymentObservation(s, b, o, now) == nil {
				t.Fatal("wrong deployment admitted")
			}
		})
	}
	principal := identity.Principal{ID: selected.ExecutorID, Kind: identity.PrincipalPolicy, Method: identity.CloudflareAccessMethod}
	executor := selected.ExecutorID
	p := generated.Plan{PlanID: selected.PlanID, PlanDigest: selected.PlanDigest, ExecutorMode: "external", ExecutorID: &executor, Extensions: []generated.ContractExtension{{Name: "x-executor-deployment-job", ValueDigest: serverconfig.CIDeploymentJobDigest(selected)}}}
	step := generated.RunStep{ExecutorID: executor, TargetID: selected.TargetID, ArtifactDigest: selected.ArtifactDigest}
	if !deploymentJobMatches(selected, principal, p, step) {
		t.Fatal("exact protected plan rejected")
	}
	for _, mode := range []string{"principal", "target", "image", "plan", "proof"} {
		t.Run(mode, func(t *testing.T) {
			pr, pp, ss := principal, p, step
			pp.Extensions = append([]generated.ContractExtension(nil), p.Extensions...)
			switch mode {
			case "principal":
				pr.ID = "build-principal"
			case "target":
				ss.TargetID = "another-service"
			case "image":
				ss.ArtifactDigest = hostaction.Digest("wrong-image")
			case "plan":
				pp.PlanDigest = hostaction.Digest("wrong-plan")
			case "proof":
				pp.Extensions = nil
			}
			if deploymentJobMatches(selected, pr, pp, ss) {
				t.Fatal("wrong protected scope admitted")
			}
		})
	}
}

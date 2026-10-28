package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/adapter/coolify"
	"github.com/vegastack/vegastack-labs/internal/adapter/githubci"
	transport "github.com/vegastack/vegastack-labs/internal/adapter/hostaction"
	"github.com/vegastack/vegastack-labs/internal/cijobrunner"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type ciExternalDeploymentControl struct {
	authority *store.Store
	profile   serverconfig.Profile
	executors *runengine.ExternalExecutor
	guard     *externalDeploymentAdmission
	broker    ciDeploymentBroker
}

func (d *ciExternalDeploymentControl) exchange(ctx context.Context, c *ciJobControl, control *cijobrunner.Control) error {
	policy, err := c.jobs.ExternalDeploymentPolicy(c.request.ExecutionBindingID)
	if err != nil {
		return err
	}
	if policy.Binding.BindingID == "" {
		return nil
	}
	if d == nil || d.authority == nil || d.executors == nil {
		return actionFailure()
	}
	companion, err := store.NewPlanRepository(d.authority).CICompanion(ctx, c.binding.PlanID)
	if err != nil {
		return err
	}
	p := companion.Plan
	nonce := make([]byte, 32)
	if _, err = rand.Read(nonce); err != nil {
		return actionFailure()
	}
	lease, err := d.executors.ClaimManaged(ctx, c.binding, p.PlanID, generated.ExecutorClaimRequest{Schema: generated.SchemaIDExecutorClaimRequest, SchemaVersion: "1.0.0", ExecutorID: policy.Binding.ExecutorID, PrincipalID: policy.Binding.ExecutorID, AdapterID: store.CIExternalDeploymentAdapter, RecoveryEpoch: c.binding.RecoveryEpoch, NonceDigest: hostaction.Digest(hex.EncodeToString(nonce)), Extensions: []generated.ContractExtension{}})
	if err != nil {
		return err
	}
	command, err := d.command(p, lease, policy)
	if err != nil {
		return err
	}
	if err = control.WriteDeploymentOffer(ctx, command); err != nil {
		return err
	}
	msg, err := control.Receive(ctx)
	if err != nil || msg.Kind != "deployment-ready" {
		return actionFailure()
	}
	if err = d.current(ctx, c.binding, p, lease); err != nil {
		return err
	}
	value, err := d.broker.ResolveAndConsume(ctx, c.binding, p, lease)
	if err != nil {
		return err
	}
	lease, err = store.NewExecutorLeaseRepository(d.authority).Get(ctx, lease.LeaseID)
	if err != nil {
		value.Close()
		return err
	}
	err = control.WriteDeployment(ctx, command, value)
	value.Close()
	if err != nil {
		return err
	}
	for {
		msg, err = control.Receive(ctx)
		if err != nil {
			return err
		}
		switch msg.Kind {
		case "deployment-check":
			if msg.DeploymentCheck == nil {
				return actionFailure()
			}
			renewAfter, parseErr := time.Parse(time.RFC3339, lease.RenewAfter)
			if parseErr != nil {
				return actionFailure()
			}
			if !time.Now().Before(renewAfter) {
				lease, err = d.executors.RenewManaged(ctx, c.binding, generated.ExecutorRenewRequest{Schema: generated.SchemaIDExecutorRenewRequest, SchemaVersion: "1.0.0", LeaseID: lease.LeaseID, BindingDigest: lease.BindingDigest, NonceDigest: lease.NonceDigest, RecoveryEpoch: lease.RecoveryEpoch, Extensions: []generated.ContractExtension{}})
				if err != nil {
					return err
				}
			}
			if err = d.current(ctx, c.binding, p, lease); err != nil {
				return err
			}
			if err = control.WriteDeploymentChecked(ctx, *msg.DeploymentCheck); err != nil {
				return err
			}
		case "deployment-result":
			result := msg.DeploymentResult
			if result == nil || result.CommandDigest != hostaction.Digest(command) {
				return actionFailure()
			}
			status := "failed"
			if result.Succeeded {
				status = "succeeded"
			}
			receipt := generated.ExecutionReceipt{Schema: generated.SchemaIDExecutionReceipt, SchemaVersion: "1.0.0", LeaseID: lease.LeaseID, PlanID: lease.PlanID, PlanDigest: lease.PlanDigest, RunID: lease.RunID, StepID: lease.StepID, OperationID: lease.OperationID, ExecutorID: lease.ExecutorID, AdapterID: lease.AdapterID, TargetID: lease.TargetID, ArtifactDigest: lease.ArtifactDigest, BindingDigest: lease.BindingDigest, NonceDigest: lease.NonceDigest, RecoveryEpoch: lease.RecoveryEpoch, ReceiptID: "ci-deploy-" + hex.EncodeToString(nonce[:16]), Status: status, ResultDigest: hostaction.Digest(result), RecordedAt: time.Now().UTC().Format(time.RFC3339), Extensions: []generated.ContractExtension{}}
			lease, err = store.NewExecutorLeaseRepository(d.authority).Get(ctx, lease.LeaseID)
			if err != nil {
				return err
			}
			_, err = d.executors.SubmitManagedReceipt(withCIExternalDeploymentReceipt(ctx, c.binding, p, lease), c.binding, generated.ExecutionReceiptRequest{Schema: generated.SchemaIDExecutionReceiptRequest, SchemaVersion: "1.0.0", Receipt: receipt, ExpectedBindingDigest: lease.BindingDigest, Extensions: []generated.ContractExtension{}})
			if err != nil {
				return err
			}
			if !result.Succeeded {
				return actionFailure()
			}
			return nil
		default:
			return actionFailure()
		}
	}
}

func (d *ciExternalDeploymentControl) command(p generated.Plan, l generated.ExecutorLease, policy store.CIExternalDeploymentPolicy) (cijobrunner.DeploymentCommand, error) {
	var service *generated.ServiceProviderBinding
	var deployment *generated.ServiceDeploymentProviderBinding
	for i := range d.profile.ServiceBindings {
		s := &d.profile.ServiceBindings[i]
		if s.ServiceID == policy.Binding.ServiceID {
			service = s
		}
	}
	for i := range d.profile.ServiceDeploymentBindings {
		s := &d.profile.ServiceDeploymentBindings[i]
		if s.Binding.ServiceID == policy.Binding.ServiceID {
			deployment = s
		}
	}
	deadline, err := time.Parse(time.RFC3339, l.MaximumExpiresAt)
	if err != nil || service == nil || service.Coolify == nil || deployment == nil {
		return cijobrunner.DeploymentCommand{}, actionFailure()
	}
	b := service.Coolify
	return cijobrunner.DeploymentCommand{PlanID: p.PlanID, PlanDigest: p.PlanDigest, RunID: l.RunID, StepID: l.StepID, LeaseID: l.LeaseID, LeaseDigest: l.BindingDigest, ReferenceID: policy.ReferenceID, MaterialVersion: policy.Binding.MaterialVersion, Epoch: uint64(l.RecoveryEpoch), Deadline: deadline, Origin: b.Origin, Target: coolify.ApplicationTarget{TeamID: b.TeamID, ProjectID: b.ProjectID, EnvironmentID: b.EnvironmentID, DestinationID: b.DestinationID, ProjectUUID: b.ProjectUUID, Environment: b.Environment, ApplicationUUID: b.ApplicationUUID, DestinationType: b.DestinationType}, DestinationUUID: deployment.DestinationUUID, ServerUUID: deployment.ServerUUID, ServerID: deployment.ServerID, Repository: policy.Artifact.Repository, Digest: policy.Artifact.Digest}, nil
}

// Configure the existing in-process host adapter before the server accepts requests.
func configureCIExternalDeployments(p serverconfig.Profile, s *store.Store, r *adapter.Registry, e *runengine.ExternalExecutor, g *store.GateRepository, guard *externalDeploymentAdmission) error {
	if len(p.CIExternalDeployments) == 0 {
		return nil
	}
	impl, err := r.Resolve(hostaction.AdapterID)
	if err != nil {
		return err
	}
	configurable, ok := impl.(interface {
		ConfigureCI(transport.CIControlFactory) error
	})
	if !ok {
		return actionFailure()
	}
	provider, err := githubci.NewClient("https://api.github.com", nil)
	if err != nil {
		return err
	}
	jobs := newCIJobRepository(s, g)
	control := &ciExternalDeploymentControl{authority: s, profile: p, executors: e, guard: guard, broker: ciDeploymentBroker{authority: s, jobs: jobs, registry: r, gates: g, destination: hostReplacementComposition{authority: s, gates: g, clock: time.Now}}}
	return configurable.ConfigureCI(ciJobControlFactory{jobs: jobs, provider: provider, deployment: control})
}

func (d *ciExternalDeploymentControl) current(ctx context.Context, parent adapter.ExactExecutionBinding, p generated.Plan, l generated.ExecutorLease) error {
	if d.guard == nil {
		return actionFailure()
	}
	r, err := store.NewRunRepository(d.authority).Get(ctx, l.RunID)
	if err != nil {
		return err
	}
	var found *generated.RunStep
	for i := range r.Steps {
		if r.Steps[i].StepID == l.StepID {
			found = &r.Steps[i]
		}
	}
	if found == nil {
		return actionFailure()
	}
	if _, err = d.guard.VerifyManagedDeploymentJob(ctx, parent, p, *found); err != nil {
		return err
	}
	return d.broker.Check(ctx, parent, p, l)
}

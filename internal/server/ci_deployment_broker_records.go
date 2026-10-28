package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// These are the broker's existing repository reads. The private seam lets the
// credential boundary be exercised with synthetic records on every client OS.
type ciDeploymentBrokerRecords interface {
	Lease(context.Context, string) (generated.ExecutorLease, error)
	Admission(context.Context, adapter.ExactExecutionBinding, generated.Plan, generated.RunStep) (store.CIManagedDeploymentAdmission, error)
	Policy(string) (store.CIExternalDeploymentPolicy, error)
	Profile(context.Context) (store.GateAppliedProfile, error)
	Reference(context.Context, string, int64) (generated.CredentialReference, error)
	Handoff(context.Context, adapter.ExactExecutionBinding, generated.Plan, generated.ExecutorLease) error
	ReadContext(context.Context, string) (context.Context, error)
}
type ciDeploymentStoredRecords struct {
	authority *store.Store
	jobs      *store.CIJobRepository
	gates     *store.GateRepository
}

func (s ciDeploymentStoredRecords) Lease(ctx context.Context, id string) (generated.ExecutorLease, error) {
	return store.NewExecutorLeaseRepository(s.authority).Get(ctx, id)
}
func (s ciDeploymentStoredRecords) Admission(ctx context.Context, b adapter.ExactExecutionBinding, p generated.Plan, step generated.RunStep) (store.CIManagedDeploymentAdmission, error) {
	return s.jobs.ManagedDeploymentAdmission(ctx, b, p, step)
}
func (s ciDeploymentStoredRecords) Policy(id string) (store.CIExternalDeploymentPolicy, error) {
	return s.jobs.ExternalDeploymentPolicy(id)
}
func (s ciDeploymentStoredRecords) Profile(ctx context.Context) (store.GateAppliedProfile, error) {
	return s.gates.GetAppliedProfileScope(ctx)
}
func (s ciDeploymentStoredRecords) Reference(ctx context.Context, id string, epoch int64) (generated.CredentialReference, error) {
	return store.NewCredentialRepository(s.authority).GetActiveVersion(ctx, id, epoch)
}
func (s ciDeploymentStoredRecords) Handoff(ctx context.Context, b adapter.ExactExecutionBinding, p generated.Plan, l generated.ExecutorLease) error {
	return s.jobs.ConsumeDeploymentHandoff(ctx, b, p, l)
}
func (s ciDeploymentStoredRecords) ReadContext(ctx context.Context, id string) (context.Context, error) {
	return s.authority.HostRunReadContext(ctx, id)
}
func (b *ciDeploymentBroker) recordSource() ciDeploymentBrokerRecords {
	if b == nil {
		return nil
	}
	if b.records != nil {
		return b.records
	}
	if b.authority == nil || b.jobs == nil || b.gates == nil {
		return nil
	}
	return ciDeploymentStoredRecords{b.authority, b.jobs, b.gates}
}

type ciDeploymentApplicationAdmission interface {
	roleAdmission(context.Context, string) (store.HostAdmissionSnapshot, error)
}

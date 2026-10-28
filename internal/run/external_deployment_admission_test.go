package run

import (
	"context"
	"errors"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"testing"
)

type deploymentAdmissionFixture struct {
	calls  int
	denied bool
	cancel func()
}

func (f *deploymentAdmissionFixture) VerifyDeploymentJob(context.Context, identity.Principal, generated.Plan, generated.RunStep) error {
	f.calls++
	if f.cancel != nil {
		f.cancel()
	}
	if f.denied {
		return errors.New("synthetic job denied")
	}
	return nil
}
func TestExternalDeploymentClaimRequiresCurrentJob(t *testing.T) {
	for _, mode := range []string{"missing", "denied", "allowed", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			f := newExternalExecutorFixture(t)
			f.engine.store.plan.Operations[0].OperationType = "application.deploy.production-like"
			run := f.engine.store.runs[f.engine.runID]
			run.Steps[0].OperationType = "application.deploy.production-like"
			f.engine.store.runs[run.RunID] = run
			guard := &deploymentAdmissionFixture{denied: mode == "denied"}
			f.external.deploymentAdmission = nil
			if mode != "missing" {
				f.external.deploymentAdmission = guard
			}
			if mode == "cancelled" {
				guard.cancel = func() {
					f.engine.store.mu.Lock()
					defer f.engine.store.mu.Unlock()
					r := f.engine.store.runs[f.engine.runID]
					r.CancellationRequested = true
					f.engine.store.runs[r.RunID] = r
				}
			}
			_, err := f.external.Claim(context.Background(), f.principal, f.claimRequest())
			if (err == nil) != (mode == "allowed") {
				t.Fatal(mode, err)
			}
			if mode != "allowed" && len(f.leases.leases) != 0 {
				t.Fatal("denied claim handed out lease")
			}
		})
	}
}
func TestExternalDeploymentRechecksBeforeRenewalAndReceipt(t *testing.T) {
	for _, action := range []string{"renew", "receipt"} {
		t.Run(action, func(t *testing.T) {
			f := newExternalExecutorFixture(t)
			f.engine.store.plan.Operations[0].OperationType = "application.deploy.production-like"
			run := f.engine.store.runs[f.engine.runID]
			run.Steps[0].OperationType = "application.deploy.production-like"
			f.engine.store.runs[run.RunID] = run
			guard := &deploymentAdmissionFixture{}
			f.external.deploymentAdmission = guard
			lease := f.claim(t)
			guard.denied = true
			if action == "renew" {
				_, err := f.external.Renew(context.Background(), f.principal, generated.ExecutorRenewRequest{Schema: generated.SchemaIDExecutorRenewRequest, SchemaVersion: "1.0.0", LeaseID: lease.LeaseID, BindingDigest: lease.BindingDigest, NonceDigest: lease.NonceDigest, RecoveryEpoch: lease.RecoveryEpoch, Extensions: []generated.ContractExtension{}})
				if err == nil {
					t.Fatal("revoked job renewed")
				}
			} else {
				if _, err := f.external.SubmitReceipt(context.Background(), f.principal, receiptRequest(lease, "receipt-a", "succeeded")); err == nil {
					t.Fatal("revoked job submitted verified receipt")
				}
			}
			if guard.calls != 2 {
				t.Fatal("admission not repeated", guard.calls)
			}
			if len(f.leases.receipts) != 0 {
				t.Fatal("denied receipt persisted")
			}
		})
	}
}

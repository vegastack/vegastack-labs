package run

import (
	"context"
	"errors"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

type managedAdmissionFixture struct {
	parentPlan         string
	calls, staticCalls int
	denied             bool
	method             string
}

func (f *managedAdmissionFixture) VerifyDeploymentJob(context.Context, identity.Principal, generated.Plan, generated.RunStep) error {
	f.staticCalls++
	return errors.New("static binding absent")
}
func (f *managedAdmissionFixture) VerifyManagedDeploymentJob(_ context.Context, parent adapter.ExactExecutionBinding, plan generated.Plan, step generated.RunStep) (identity.Principal, error) {
	f.calls++
	if f.denied || parent.PlanDigest != f.parentPlan || plan.ExecutorID == nil || *plan.ExecutorID != step.ExecutorID {
		return identity.Principal{}, errors.New("current consumed admission denied")
	}
	method := f.method
	if method == "" {
		method = identity.ManagedCIControllerMethod
	}
	return identity.Principal{ID: step.ExecutorID, Kind: identity.PrincipalPolicy, Method: method}, nil
}
func managedFixture(t *testing.T) (*externalExecutorFixture, *managedAdmissionFixture, adapter.ExactExecutionBinding) {
	t.Helper()
	f := newExternalExecutorFixture(t)
	f.engine.store.plan.Operations[0].OperationType = "application.deploy.production-like"
	r := f.engine.store.runs[f.engine.runID]
	r.Steps[0].OperationType = "application.deploy.production-like"
	f.engine.store.runs[r.RunID] = r
	parent := adapter.ExactExecutionBinding{PlanID: "parent-plan", PlanDigest: digest("parent"), RunID: "parent-run", StepID: "parent-step", LeaseID: "parent-lease"}
	guard := &managedAdmissionFixture{parentPlan: parent.PlanDigest}
	f.external.deploymentAdmission = guard
	return f, guard, parent
}
func TestManagedClaimCannotBeFabricatedByPrincipal(t *testing.T) {
	f, guard, parent := managedFixture(t)
	principal := identity.Principal{ID: f.principal.ID, Method: identity.ManagedCIControllerMethod, Kind: identity.PrincipalPolicy}
	if _, e := f.external.Claim(context.Background(), principal, f.claimRequest()); e == nil {
		t.Fatal("literal managed principal bypassed proof")
	}
	if guard.calls != 0 || len(f.leases.leases) != 0 {
		t.Fatal("unverified caller reached guard/lease")
	}
	wrong := parent
	wrong.PlanDigest = digest("wrong")
	if _, e := f.external.ClaimManaged(context.Background(), wrong, f.engine.store.plan.PlanID, f.claimRequest()); e == nil {
		t.Fatal("wrong parent admitted")
	}
	guard.method = identity.CloudflareAccessMethod
	if _, e := f.external.ClaimManaged(context.Background(), parent, f.engine.store.plan.PlanID, f.claimRequest()); e == nil {
		t.Fatal("fabricated transport identity accepted")
	}
	if len(f.leases.leases) != 0 {
		t.Fatal("denied claim created lease")
	}
}
func TestManagedClaimRevalidatesBeforeRenewalAndReceipt(t *testing.T) {
	for _, action := range []string{"renew", "receipt"} {
		t.Run(action, func(t *testing.T) {
			f, guard, parent := managedFixture(t)
			lease, e := f.external.ClaimManaged(context.Background(), parent, f.engine.store.plan.PlanID, f.claimRequest())
			if e != nil {
				t.Fatal(e)
			}
			if guard.calls != 2 || guard.staticCalls != 0 {
				t.Fatal("managed claim did not revalidate", guard.calls, guard.staticCalls)
			}
			guard.denied = true
			if action == "renew" {
				_, e = f.external.RenewManaged(context.Background(), parent, generated.ExecutorRenewRequest{Schema: generated.SchemaIDExecutorRenewRequest, SchemaVersion: "1.0.0", LeaseID: lease.LeaseID, BindingDigest: lease.BindingDigest, NonceDigest: lease.NonceDigest, RecoveryEpoch: lease.RecoveryEpoch, Extensions: []generated.ContractExtension{}})
			} else {
				_, e = f.external.SubmitManagedReceipt(context.Background(), parent, receiptRequest(lease, "managed-receipt", "succeeded"))
			}
			if e == nil || len(f.leases.receipts) != 0 {
				t.Fatal("revoked admission renewed/received effect")
			}
			principal := identity.Principal{ID: f.principal.ID, Method: identity.ManagedCIControllerMethod, Kind: identity.PrincipalPolicy}
			if _, e = f.external.SubmitReceipt(context.Background(), principal, receiptRequest(lease, "forged-receipt", "succeeded")); e == nil {
				t.Fatal("literal principal reused managed lease")
			}
		})
	}
}

func TestManagedInheritedCredentialManifestDoesNotOpenOrdinaryClaims(t *testing.T) {
	f, guard, parent := managedFixture(t)
	f.engine.store.plan.Extensions = []generated.ContractExtension{{Name: "x-credential-bindings", ValueDigest: digest("protected-parent-manifest")}}
	if _, e := f.external.Claim(context.Background(), f.principal, f.claimRequest()); Code(e) != generated.ErrorCodePrerequisiteBlocked {
		t.Fatal("ordinary credential claim changed", e)
	}
	guard.denied = true
	if _, e := f.external.ClaimManaged(context.Background(), parent, f.engine.store.plan.PlanID, f.claimRequest()); e == nil {
		t.Fatal("manifest admitted without durable guard")
	}
	if len(f.leases.leases) != 0 {
		t.Fatal("unverified credential claim created lease")
	}
	guard.denied = false
	if _, e := f.external.ClaimManaged(context.Background(), parent, f.engine.store.plan.PlanID, f.claimRequest()); e != nil {
		t.Fatal("exact managed companion rejected", e)
	}
	if guard.staticCalls != 0 || f.engine.adapter.calls != 0 {
		t.Fatal("claim called static admission or provider")
	}
}

package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/identity"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
	"time"
)

type controllerSetupRuns struct{ *runengine.Engine }

func (r controllerSetupRuns) Submit(ctx context.Context, q runengine.SubmitRequest) (generated.Run, error) {
	return r.SubmitControllerSetup(ctx, q)
}

type controllerSetupClaims struct {
	authority     *store.Store
	runs          *store.RunRepository
	plans         *store.PlanRepository
	verifier      *controllerSetupPilotVerifier
	profile       serverconfig.Profile
	clock         func() time.Time
	validateInput func(context.Context, generated.Plan, string) error
	preconditions func(context.Context, generated.Plan, string) error
	observe       func(context.Context, generated.Plan, string) (string, error)
}

func (c *controllerSetupClaims) Validate(ctx context.Context, p generated.Plan, raw string) (generated.ControllerSetupPilotPolicy, error) {
	if c == nil || c.verifier == nil || c.verifier.policy == nil || c.validateInput == nil || !runengine.ControllerSetupPlan(p) {
		return generated.ControllerSetupPilotPolicy{}, actionFailure()
	}
	if _, e := c.verifier.Verify(ctx, p); e != nil {
		return generated.ControllerSetupPilotPolicy{}, e
	}
	policy := *c.verifier.policy
	bound := false
	for _, binding := range c.profile.PrincipalBindings {
		if binding.PrincipalID == policy.AdministratorPrincipalID && int64(binding.UID) != policy.AdministratorUID {
			return generated.ControllerSetupPilotPolicy{}, actionFailure()
		}
		if int64(binding.UID) == policy.AdministratorUID && binding.PrincipalID == policy.AdministratorPrincipalID {
			bound = true
		}
	}
	if !bound {
		return generated.ControllerSetupPilotPolicy{}, actionFailure()
	}
	if e := c.validateInput(ctx, p, raw); e != nil {
		return generated.ControllerSetupPilotPolicy{}, e
	}
	return policy, nil
}
func controllerClaimDigest(p generated.Plan, r generated.Run, l generated.ExecutorLease, policy generated.ControllerSetupPilotPolicy, principal string) string {
	return hostaction.Digest([]string{p.PlanID, p.PlanDigest, r.RunID, l.LeaseID, hostaction.Digest(policy), p.Operations[0].InputDigest, principal, l.MaximumExpiresAt})
}
func (c *controllerSetupClaims) Claim(ctx context.Context, p generated.Plan, r generated.Run, raw string, principal identity.Principal) (generated.ControllerSetupClaim, error) {
	var zero generated.ControllerSetupClaim
	policy, e := c.Validate(ctx, p, raw)
	if e != nil {
		return zero, e
	}
	if principal.ID != policy.AdministratorPrincipalID || principal.Method != identity.LocalOSPeerMethod || identity.EffectivePrincipalKind(principal) != identity.PrincipalHuman || r.Status != "running" || len(r.Steps) != 1 || r.Steps[0].Status != "queued" || r.Steps[0].EffectState != "not-started" || r.PlanID != p.PlanID || r.PlanDigest != p.PlanDigest {
		return zero, actionFailure()
	}
	if c.preconditions == nil || c.preconditions(ctx, p, raw) != nil {
		return zero, actionFailure()
	}
	a, e := c.authority.HostAccessRunAttribution(ctx, r.RunID)
	if e != nil || a.AuthenticatedPrincipalID != principal.ID {
		return zero, actionFailure()
	}
	now := c.clock().UTC().Truncate(time.Second)
	expires := now.Add(time.Duration(generated.ExecutorLeaseSeconds) * time.Second)
	planExpiry, e := time.Parse(time.RFC3339, p.ExpiresAt)
	if e != nil || expires.After(planExpiry) {
		return zero, actionFailure()
	}
	policyExpiry, e := time.Parse(time.RFC3339, policy.ExpiresAt)
	if e != nil || expires.After(policyExpiry) {
		return zero, actionFailure()
	}
	var nonce [32]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return zero, e
	}
	step := r.Steps[0]
	lease := generated.ExecutorLease{Schema: generated.SchemaIDExecutorLease, SchemaVersion: "1.0.0", LeaseID: "controller-lease-" + hex.EncodeToString(nonce[:16]), PlanID: p.PlanID, PlanDigest: p.PlanDigest, RunID: r.RunID, StepID: step.StepID, OperationID: step.OperationID, ExecutorID: step.ExecutorID, AdapterID: step.AdapterID, TargetID: step.TargetID, ArtifactDigest: step.ArtifactDigest, BindingDigest: r.ExecutorBindingDigest, NonceDigest: hostaction.Digest(nonce[:]), RecoveryEpoch: r.RecoveryEpoch, ClaimedAt: now.Format(time.RFC3339), RenewAfter: now.Add(time.Duration(generated.ExecutorCheckInSeconds) * time.Second).Format(time.RFC3339), LeaseExpiresAt: expires.Format(time.RFC3339), MaximumExpiresAt: expires.Format(time.RFC3339), Status: "active"}
	digest := controllerClaimDigest(p, r, lease, policy, principal.ID)
	lease.Extensions = []generated.ContractExtension{{Name: "x-controller-setup-claim", ValueDigest: digest}}
	if e = c.runs.AcquireTargetLease(ctx, lease, a); e != nil {
		return zero, e
	}
	running, e := c.runs.BeginStep(ctx, store.StepBeginRequest{RunID: r.RunID, StepID: step.StepID, LeaseID: lease.LeaseID, At: now, Attribution: a})
	if e != nil {
		return zero, e
	}
	return generated.ControllerSetupClaim{Schema: generated.SchemaIDControllerSetupClaim, SchemaVersion: "1.0.0", Plan: p, Run: running, Lease: lease, Policy: policy, InputJSON: raw, ClaimDigest: digest, ExpiresAt: lease.MaximumExpiresAt}, nil
}
func (c *controllerSetupClaims) SubmitReceipt(ctx context.Context, q generated.ControllerSetupReceiptRequest, principal identity.Principal) (generated.Run, error) {
	var zero generated.Run
	r, e := c.runs.GetRun(ctx, q.RunID)
	if e != nil {
		return zero, e
	}
	stored, e := c.plans.GetPlan(ctx, r.PlanID)
	if e != nil {
		return zero, e
	}
	p := stored.Plan
	policy, e := c.Validate(ctx, p, q.InputJSON)
	if e != nil {
		return zero, e
	}
	if principal.ID != policy.AdministratorPrincipalID || principal.Method != identity.LocalOSPeerMethod || identity.EffectivePrincipalKind(principal) != identity.PrincipalHuman || q.RecoveryEpoch != p.Binding.RecoveryEpoch {
		return zero, actionFailure()
	}
	l, e := c.runs.ControllerSetupLease(ctx, q.RunID, q.LeaseID)
	if e != nil {
		return zero, e
	}
	deadline, e := time.Parse(time.RFC3339, l.MaximumExpiresAt)
	if e != nil || !c.clock().UTC().Before(deadline) || generated.ValidateExecutorLeaseBinding(p, r, l) != nil || controllerClaimDigest(p, r, l, policy, principal.ID) != q.ClaimDigest {
		return zero, actionFailure()
	}
	found := false
	for _, x := range l.Extensions {
		if x.Name == "x-controller-setup-claim" && x.ValueDigest == q.ClaimDigest {
			found = true
		}
	}
	if !found {
		return zero, actionFailure()
	}
	a, e := c.authority.HostAccessRunAttribution(ctx, r.RunID)
	if e != nil || a.AuthenticatedPrincipalID != principal.ID {
		return zero, actionFailure()
	}
	status, verification := "partial", hostaction.Digest([]string{"controller-setup-unverified", q.ClaimDigest, q.ResultDigest})
	if c.observe != nil && q.Status == "installed-awaiting-native-verification" {
		actual, err := c.observe(ctx, p, q.InputJSON)
		if err == nil && actual == q.ResultDigest {
			status, verification = "succeeded", actual
		}
	}
	// Recheck current authority after observing actual files and before recording.
	if _, e = c.Validate(ctx, p, q.InputJSON); e != nil {
		return zero, e
	}
	if _, e = c.runs.ControllerSetupLease(ctx, q.RunID, q.LeaseID); e != nil {
		return zero, e
	}
	now := c.clock().UTC().Truncate(time.Second)
	receipt := generated.ExecutionReceipt{Schema: generated.SchemaIDExecutionReceipt, SchemaVersion: "1.0.0", ReceiptID: "controller-receipt-" + hostaction.Digest(q.LeaseID)[7:39], LeaseID: l.LeaseID, PlanID: l.PlanID, PlanDigest: l.PlanDigest, RunID: l.RunID, StepID: l.StepID, OperationID: l.OperationID, ExecutorID: l.ExecutorID, AdapterID: l.AdapterID, TargetID: l.TargetID, ArtifactDigest: l.ArtifactDigest, BindingDigest: l.BindingDigest, NonceDigest: l.NonceDigest, RecoveryEpoch: l.RecoveryEpoch, Status: status, ResultDigest: q.ResultDigest, RecordedAt: now.Format(time.RFC3339), Extensions: []generated.ContractExtension{}}
	if _, e = c.runs.RecordReceipt(ctx, store.ReceiptRecordRequest{RunID: r.RunID, StepID: l.StepID, LeaseID: l.LeaseID, Receipt: receipt, At: now, Attribution: a}); e != nil {
		return zero, e
	}
	if _, e = c.runs.FinishStep(ctx, store.StepFinishRequest{RunID: r.RunID, StepID: l.StepID, LeaseID: l.LeaseID, Receipt: receipt, Status: status, EffectState: "verified", VerificationDigest: verification, Changed: true, At: now, Attribution: a}); e != nil {
		return zero, e
	}
	if e = c.runs.ReleaseTargetLease(ctx, l.LeaseID, now); e != nil {
		return zero, e
	}
	verified, rollback := "verified", "not-requested"
	if status != "succeeded" {
		verified, rollback = "incomplete", "separate-plan"
	}
	changed := true
	return c.runs.TransitionRun(ctx, store.RunTransitionRequest{RunID: r.RunID, From: "running", To: status, At: now, VerificationStatus: verified, VerificationDigest: &verification, RollbackStatus: rollback, Changed: &changed, Attribution: a})
}

var _ api.ControllerSetupLifecycle = (*controllerSetupClaims)(nil)

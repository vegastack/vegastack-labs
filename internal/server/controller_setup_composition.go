package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/linuxrole"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
	"time"
)

func newControllerSetupClaims(a *store.Store, r *store.RunRepository, p *store.PlanRepository, v *controllerSetupPilotVerifier, profile serverconfig.Profile, clock func() time.Time) *controllerSetupClaims {
	c := &controllerSetupClaims{authority: a, runs: r, plans: p, verifier: v, profile: profile, clock: clock}
	c.validateInput = func(ctx context.Context, plan generated.Plan, raw string) error {
		in, e := linuxrole.DecodeControllerInstallInput([]byte(raw))
		if e != nil || v == nil || v.policy == nil {
			return actionFailure()
		}
		policy := *v.policy
		if len(plan.Operations) != 1 || hostaction.Digest(in) != plan.Operations[0].InputDigest || in.ControllerSetupPilotDigest != hostaction.Digest(policy) || in.ControllerInstanceID != policy.ControllerInstanceID || in.ControllerMachineIDDigest != policy.ControllerMachineIDDigest || in.RecoveryEpoch != policy.RecoveryEpoch || in.StateRevision != plan.Binding.StateRevision || in.RecoveryImageDigest != policy.RecoveryImageDigest || in.ServiceUID != policy.ServiceUID || in.ServiceGID != policy.ServiceGID || in.AdministratorUID != policy.AdministratorUID || in.AdministratorGID != policy.AdministratorGID || in.ExecutableDigest != policy.ExecutableDigest {
			return actionFailure()
		}
		return verifyControllerRecoveryImage(ctx, in)
	}
	c.preconditions = func(ctx context.Context, _ generated.Plan, raw string) error {
		in, e := linuxrole.DecodeControllerInstallInput([]byte(raw))
		if e != nil {
			return e
		}
		return linuxrole.VerifyControllerInstallPreconditions(ctx, in)
	}
	c.observe = func(ctx context.Context, _ generated.Plan, raw string) (string, error) {
		in, e := linuxrole.DecodeControllerInstallInput([]byte(raw))
		if e != nil {
			return "", e
		}
		return linuxrole.VerifyControllerInstallResult(ctx, in)
	}
	return c
}

package qualification

import (
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/linuxrole"
)

// ControlSetupAuthority is the server's independently resolved initialization
// lineage. No public request or protected witness supplies these database facts.
type ControlSetupAuthority struct {
	SetupID, RequestDigest, ReviewDigest, InstanceID, HumanID, AuthorityID, InitializedAt string
	RecoveryEpoch, InitialEventID                                                         int64
	InitialEventDigest, InitialChainDigest                                                string
	VerifiedRestoreBinding                                                                *generated.RestoreBinding
}

func ValidateControlSetupEvidence(e ProducerExecution, a ControlSetupAuthority, w generated.NativeControlSetupWitness, o generated.NativeObservation) error {
	if !exactNativeJSON(generated.SchemaIDNativeControlSetupWitness, w) || e.Reference.ScenarioID != "control-setup" || e.Plan.HostAction == nil || e.Plan.HostRoleScope == nil || e.Plan.HostRoleScope.RoleID != "control" || e.Receipt.Status != "succeeded" || e.Result == nil || e.Result.Status != "succeeded" || a.InitialEventID <= 0 || a.InitialEventDigest == "" || a.InitialChainDigest == "" || a.HumanID == "" || a.AuthorityID == "" {
		return ErrUnavailable
	}
	s := w.FixtureScope
	if !s.RunControlSetup || w.ScopeDigest != hostaction.Digest(s) || s.ExecutableDigest != o.ExecutableDigest || w.SetupID != s.SetupPlanID || w.SetupRequestDigest != s.SetupRequestDigest || w.SetupReviewDigest != s.SetupPlanDigest || a.SetupID != w.SetupID || a.RequestDigest != w.SetupRequestDigest || a.ReviewDigest != w.SetupReviewDigest || a.InstanceID != w.InstanceID || a.RecoveryEpoch != w.RecoveryEpoch || w.RecoveryEpoch != 0 || len(w.Attempts) != 6 || w.InitialPID == w.FinalPID || w.InitialStartIdentity == w.FinalStartIdentity {
		return ErrUnavailable
	}
	in, err := linuxrole.DecodeInput([]byte(e.Plan.HostAction.ActionInput))
	if err != nil || in.RoleID != "control" || in.HostID != e.Reference.HostID {
		return ErrUnavailable
	}
	if a.VerifiedRestoreBinding == nil {
		if o.Binding.ControllerInstanceID != w.InstanceID || e.Plan.Binding.RecoveryEpoch != w.RecoveryEpoch || in.HostIdentityDigest != s.HostIdentityDigest {
			return ErrUnavailable
		}
	} else {
		b := a.VerifiedRestoreBinding
		if b.PriorInstanceID != w.InstanceID || b.PriorRecoveryEpoch != w.RecoveryEpoch || b.NewInstanceID != o.Binding.ControllerInstanceID || b.NextRecoveryEpoch != e.Plan.Binding.RecoveryEpoch || b.NextRecoveryEpoch != b.PriorRecoveryEpoch+1 || b.ReplacementHostID != in.HostID {
			return ErrUnavailable
		}
	}
	issued, err := time.Parse(time.RFC3339Nano, s.IssuedAt)
	expires, ee := time.Parse(time.RFC3339Nano, s.ExpiresAt)
	observed, oe := time.Parse(time.RFC3339Nano, w.ObservedAt)
	outer, te := time.Parse(time.RFC3339Nano, o.ObservedAt)
	initialized, ie := time.Parse(time.RFC3339Nano, a.InitializedAt)
	if err != nil || ee != nil || oe != nil || te != nil || ie != nil || expires.Sub(issued) > 4*time.Hour || !expires.After(issued) || observed.Before(issued) || outer.Before(observed) || !outer.Before(expires) || initialized.Before(issued) || initialized.After(observed) {
		return ErrUnavailable
	}
	return validateSetupAttempts(w, issued, observed)
}

func validateSetupAttempts(w generated.NativeControlSetupWitness, issued, observed time.Time) error {
	if len(w.Attempts) != 6 {
		return ErrUnavailable
	}
	kinds := []string{"incomplete-refusal", "fresh", "populated-refusal", "writer-refusal", "restart", "crash-restart"}
	last := issued
	for i, attempt := range w.Attempts {
		at, err := time.Parse(time.RFC3339Nano, attempt.ObservedAt)
		if err != nil || at.Before(last) || at.After(observed) || attempt.Kind != kinds[i] || attempt.PID <= 1 || attempt.StartIdentity == "" {
			return ErrUnavailable
		}
		last = at
		if i == 0 || i == 2 || i == 3 {
			if attempt.BeforeDigest != attempt.AfterDigest || attempt.ErrorCode != "STATE_CONFLICT" {
				return ErrUnavailable
			}
		} else if attempt.ErrorCode != "" || attempt.InstanceID != w.InstanceID {
			return ErrUnavailable
		}
	}
	if w.Attempts[1].BeforeDigest == w.Attempts[1].AfterDigest || w.Attempts[1].PID != w.InitialPID || w.Attempts[1].StartIdentity != w.InitialStartIdentity || w.Attempts[5].PID != w.FinalPID || w.Attempts[5].StartIdentity != w.FinalStartIdentity || w.Attempts[4].StartIdentity == w.Attempts[5].StartIdentity {
		return ErrUnavailable
	}
	return nil
}

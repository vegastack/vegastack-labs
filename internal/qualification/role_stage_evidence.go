package qualification

import (
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/linuxrole"
)

func validateRoleScenarioEvidence(scenario string, executions []ProducerExecution, observations []generated.NativeObservation) error {
	if len(executions) == 0 || len(executions) != len(observations) {
		return ErrUnavailable
	}
	switch scenario {
	case "control-setup":
		if len(executions) != 1 || executions[0].ControlSetupAuthority == nil || observations[0].ControlSetup == nil {
			return ErrUnavailable
		}
		return ValidateControlSetupEvidence(executions[0], *executions[0].ControlSetupAuthority, *observations[0].ControlSetup, observations[0])
	case "control-handoff":
		if len(executions) != 2 {
			return ErrUnavailable
		}
		var original, verified *ProducerExecution
		var witness *generated.NativeControlHandoffWitness
		var at time.Time
		for i := range executions {
			e, o := &executions[i], observations[i]
			if e.Plan.HostAction == nil {
				return ErrUnavailable
			}
			switch e.Plan.HostAction.ActionID {
			case "debian.control.handoff":
				if original != nil {
					return ErrUnavailable
				}
				original = e
			case "debian.control.handoff.verify":
				if verified != nil || o.ControlHandoff == nil || e.ControlSetupAuthority == nil {
					return ErrUnavailable
				}
				verified = e
				witness = o.ControlHandoff
				var err error
				at, err = time.Parse(time.RFC3339Nano, o.ObservedAt)
				if err != nil {
					return ErrUnavailable
				}
			default:
				return ErrUnavailable
			}
		}
		if original == nil || verified == nil || witness == nil || ValidateOriginalControlHandoffEvidence(*original, *witness) != nil || ValidateControlHandoffEvidence(*verified, *witness, at) != nil {
			return ErrUnavailable
		}
		a := verified.ControlSetupAuthority
		if a.InitialEventID <= 0 || !nativeDigest(a.InitialChainDigest) || !nativeDigest(a.InitialEventDigest) {
			return ErrUnavailable
		}
		if a.InstanceID != witness.RecordedState.DatabaseInstanceID || a.RecoveryEpoch != witness.RecordedState.RecoveryEpoch {
			b := a.VerifiedRestoreBinding
			if b == nil || b.PriorInstanceID != a.InstanceID || b.PriorRecoveryEpoch != a.RecoveryEpoch || b.NewInstanceID != witness.RecordedState.DatabaseInstanceID || b.NextRecoveryEpoch != witness.RecordedState.RecoveryEpoch || b.ReplacementHostID != witness.Input.HostID {
				return ErrUnavailable
			}
		}
		return nil
	case "role-application", "role-ci", "role-reserve":
		return validateRoleInstallMeasurements(scenario, executions)
	case "replacement-recovery":
		if len(executions) != 1 || executions[0].ReplacementRecovery == nil || observations[0].ReplacementRecovery == nil || ValidateReplacementRecoveryEvidence(executions[0], *executions[0].ReplacementRecovery) != nil {
			return ErrUnavailable
		}
		return validateReplacementRecoveryNegatives(executions[0], *observations[0].ReplacementRecovery, observations[0])
	}
	return ErrUnavailable
}

func validateRoleInstallMeasurements(scenario string, executions []ProducerExecution) error {
	role := map[string]string{"role-application": "application", "role-ci": "ci", "role-reserve": "reserve"}[scenario]
	if role == "" {
		return ErrUnavailable
	}
	var binding, host, identity string
	var applyRevision int64
	var collected, networking bool
	controls := map[string]bool{}
	for _, e := range executions {
		p := e.Plan
		if p.HostAction == nil || p.HostRoleScope == nil || p.HostRoleScope.RoleID != role || e.Result == nil {
			return ErrUnavailable
		}
		in, err := linuxrole.DecodeInput([]byte(p.HostAction.ActionInput))
		if err != nil || in.RoleID != role || in.HostID != e.Reference.HostID || in.RoleBindingDigest != p.HostRoleScope.RoleBindingDigest {
			return ErrUnavailable
		}
		if binding == "" {
			binding, host, identity = in.RoleBindingDigest, in.HostID, in.HostIdentityDigest
			networking = in.NetworkingRequired
		} else if binding != in.RoleBindingDigest || host != in.HostID || identity != in.HostIdentityDigest {
			return ErrUnavailable
		}
		if p.HostAction.ActionID == "debian.role.apply" {
			if applyRevision != 0 || !(e.Receipt.Status == "partial" && e.Result.Status == "partial" || e.Receipt.Status == "succeeded" && e.Result.Status == "succeeded") || !e.Result.EffectObserved {
				return ErrUnavailable
			}
			applyRevision = p.Binding.StateRevision
			continue
		}
		if p.HostAction.ActionID != "debian.role.collect" || e.Receipt.Status != "succeeded" || e.Result.Status != "succeeded" {
			return ErrUnavailable
		}
		collected = true
		for _, m := range e.Result.ControlMeasurements {
			if m.Role == nil || m.Role.RoleID != role || m.Role.RoleBindingDigest != binding || m.SubjectHostID != host || m.SubjectIdentityDigest != identity || m.Status != "passed" || m.ConfigurationDigest != hostaction.Digest(in) {
				return ErrUnavailable
			}
			if m.ControlID == "linux.role-network-boundary" {
				if m.Role.Verification != "configuration-observed" {
					return ErrUnavailable
				}
			} else if m.Role.Verification != "effective-probe" {
				return ErrUnavailable
			}
			controls[m.ControlID] = true
		}
	}
	if applyRevision <= 0 || !collected {
		return ErrUnavailable
	}
	for _, e := range executions {
		if e.Plan.HostAction.ActionID == "debian.role.collect" && e.Plan.Binding.StateRevision <= applyRevision {
			return ErrUnavailable
		}
	}
	wanted := []string{"linux.role-identity-paths", "linux.role-service-resources"}
	if role == "reserve" {
		wanted = append(wanted, "linux.reserve-no-workloads")
		if networking {
			wanted = append(wanted, "linux.role-network-boundary")
		}
	} else {
		wanted = append(wanted, "linux.role-workload-isolation", "linux.role-network-boundary")
	}
	for _, id := range wanted {
		if !controls[id] {
			return ErrUnavailable
		}
	}
	return nil
}

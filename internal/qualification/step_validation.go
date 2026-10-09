package qualification

import (
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"time"
)

var scenarioCatalog = []string{"baseline-access", "baseline-controls", "access-idempotence", "access-rollback-timeout", "access-rollback-reboot", "action-replay", "action-concurrency", "fail2ban-window", "container-network", "volume-effective-mapping", "volume-recovery-positive", "volume-wrong-key", "volume-wrong-header", "volume-wrong-slot", "volume-wrong-mapping", "volume-revoked-binding", "volume-unchanged-after-verification", "volume-inconsistent-redundant-header", "volume-status-no-original-repair", "volume-sealed-copy-write-refused", "native-credential-lifecycle", "control-setup", "control-handoff", "role-application", "role-ci", "role-reserve", "replacement-recovery"}

func knownScenario(id string) bool {
	for _, s := range scenarioCatalog {
		if id == s {
			return true
		}
	}
	return false
}

func validateStep(s validatedNativeScope, in generated.NativeStepRequest, now time.Time) error {
	raw, err := json.Marshal(in)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDNativeStepRequest, raw, generated.ContractExact) != nil || in.ScopeDigest != s.digest || !knownScenario(in.ScenarioID) {
		return ErrUnavailable
	}
	if _, exists := s.guests[in.GuestID]; !exists {
		return ErrUnavailable
	}
	deadline, err := time.Parse(time.RFC3339, in.Deadline)
	expires, _ := time.Parse(time.RFC3339, s.value.ExpiresAt)
	if !scopeCurrent(s, now) || deadline.After(expires) || err != nil || !deadline.After(now) || deadline.Sub(now) > time.Duration(s.value.MaximumDurationSeconds)*time.Second || in.ControllerInstanceID != s.value.ControllerInstanceID {
		return ErrUnavailable
	}
	if in.Operation == "collect-native" || in.Operation == "cleanup-native" {
		if in.PlanID != "" || in.PlanDigest != "" || in.RunID != "" || in.StepID != "" || in.LeaseID != "" {
			return ErrUnavailable
		}
		return nil
	}
	if in.PlanID == "" || in.PlanDigest == "" {
		return ErrUnavailable
	}
	if in.Operation == "execute" {
		if in.RunID != "" || in.StepID != "" || in.LeaseID != "" {
			return ErrUnavailable
		}
	} else if in.RunID == "" || in.StepID == "" || in.LeaseID == "" {
		return ErrUnavailable
	}
	return nil
}

// StageScenarios returns a copy of the closed native scenario catalog.
func StageScenarios(stage string) []string {
	var out []string
	for _, scenario := range scenarioCatalog {
		group := "baseline"
		switch scenario {
		case "control-setup", "control-handoff", "role-application", "role-ci", "role-reserve":
			group = "role"
		case "replacement-recovery":
			group = "recovery"
		}
		if group == stage {
			out = append(out, scenario)
		}
	}
	return out
}

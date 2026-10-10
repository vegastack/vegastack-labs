package qualification

import (
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

// ProducerExecution is resolved by the server from authoritative execution
// records. It is not a request/report type and has no public ingestion route.
type ProducerExecution struct {
	Reference             generated.NativeProducerReference
	Plan                  generated.Plan
	Receipt               generated.ExecutionReceipt
	Result                *generated.HostActionResult
	ReplacementRecovery   *ReplacementRecoveryEvidence
	ControlSetupAuthority *ControlSetupAuthority
	Credential            *NativeCredentialEvidence
}

func SourceDigest(scope generated.QualificationScope) string {
	return hostaction.Digest(struct {
		SourceCommit     string `json:"sourceCommit"`
		ExecutableDigest string `json:"executableDigest"`
	}{scope.SourceCommit, scope.ExecutableDigest})
}

// ValidateStageEvidence checks actual producer-to-observer bindings before any
// scenario predicate. Presence in the catalog, a succeeded receipt, or a healthy
// VM alone cannot qualify a native scenario.
func ValidateStageEvidence(stage string, executions []ProducerExecution, observations []generated.NativeObservation) error {
	wanted := StageScenarios(stage)
	if len(wanted) == 0 || len(executions) == 0 || len(executions) > 64 || len(observations) != len(executions) {
		return ErrUnavailable
	}
	byScenario := map[string][]ProducerExecution{}
	byObservation := map[string][]generated.NativeObservation{}
	seen := map[string]bool{}
	nonces := map[string]bool{}
	var scopeDigest, controller, executable string
	var epoch int64
	for i, e := range executions {
		r, p, receipt, o := e.Reference, e.Plan, e.Receipt, observations[i]
		if !slices.Contains(wanted, r.ScenarioID) || !exactNativeJSON(generated.SchemaIDNativeProducerReference, r) || !exactNativeJSON(generated.SchemaIDExecutionReceipt, receipt) || !exactNativeJSON(generated.SchemaIDNativeObservation, o) {
			return ErrUnavailable
		}
		key := r.ScenarioID + ":" + r.RunID + ":" + r.StepID
		if seen[key] || nonces[o.Binding.Nonce] || r.PlanID != p.PlanID || r.PlanDigest != p.PlanDigest || receipt.PlanID != p.PlanID || receipt.PlanDigest != p.PlanDigest || receipt.RunID != r.RunID || receipt.StepID != r.StepID || receipt.LeaseID != r.LeaseID || receipt.RecoveryEpoch != p.Binding.RecoveryEpoch {
			return ErrUnavailable
		}
		seen[key], nonces[o.Binding.Nonce] = true, true
		b := o.Binding
		if b.ScenarioID != r.ScenarioID || b.PlanID != r.PlanID || b.PlanDigest != r.PlanDigest || b.RunID != r.RunID || b.StepID != r.StepID || b.LeaseID != r.LeaseID || b.RecoveryEpoch != receipt.RecoveryEpoch || o.ProcessState != "running" || o.ConsoleState != "healthy" {
			return ErrUnavailable
		}
		at, err := time.Parse(time.RFC3339, o.ObservedAt)
		deadline, de := time.Parse(time.RFC3339, b.Deadline)
		if err != nil || de != nil || !at.Before(deadline) || deadline.Sub(at) > 30*time.Second {
			return ErrUnavailable
		}
		if i == 0 {
			scopeDigest, controller, executable, epoch = b.ScopeDigest, b.ControllerInstanceID, o.ExecutableDigest, b.RecoveryEpoch
		} else if scopeDigest != b.ScopeDigest || controller != b.ControllerInstanceID || executable != o.ExecutableDigest || epoch != b.RecoveryEpoch {
			return ErrUnavailable
		}
		if e.Result != nil && (hostaction.ValidateResult(*e.Result) != nil || e.Result.ResultDigest != receipt.ResultDigest) {
			return ErrUnavailable
		}
		byScenario[r.ScenarioID] = append(byScenario[r.ScenarioID], e)
		byObservation[r.ScenarioID] = append(byObservation[r.ScenarioID], o)
	}
	for _, scenario := range wanted {
		if len(byScenario[scenario]) == 0 {
			return fmt.Errorf("%w: missing scenario %s", ErrUnavailable, scenario)
		}
		if err := validateScenarioEvidence(scenario, byScenario[scenario], byObservation[scenario]); err != nil {
			return err
		}
	}
	return nil
}

func exactNativeJSON(schema string, v any) bool {
	raw, err := json.Marshal(v)
	return err == nil && generated.ValidateContractJSON(schema, raw, generated.ContractExact) == nil
}

func validateScenarioEvidence(scenario string, executions []ProducerExecution, observations []generated.NativeObservation) error {
	if isVolumeCaseScenario(scenario) {
		return validateVolumeCaseExecutions(scenario, executions, observations)
	}
	switch scenario {
	case "baseline-access", "baseline-controls", "access-idempotence", "container-network":
		return validateBaselineScenarioEvidence(scenario, executions, observations)
	case "native-credential-lifecycle":
		return validateCredentialScenarioEvidence(executions, observations)
	case "action-replay", "action-concurrency":
		return ValidateActionProtocolEvidence(scenario, executions, observations)
	case "control-setup", "control-handoff", "role-application", "role-ci", "role-reserve", "replacement-recovery":
		return validateRoleScenarioEvidence(scenario, executions, observations)
	case "access-rollback-timeout", "access-rollback-reboot":
		return validateRollbackExecutions(scenario, executions, observations)
	case "fail2ban-window":
		return validateFail2banExecutions(executions, observations)
	case "volume-sealed-copy-write-refused":
		return validateVolumeSealExecutions(executions, observations)
	}
	return fmt.Errorf("%w: native scenario predicates unavailable: %s", ErrUnavailable, scenario)
}

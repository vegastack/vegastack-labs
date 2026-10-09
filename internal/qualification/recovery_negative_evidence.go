package qualification

import (
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostreplacement"
)

func validateReplacementRecoveryNegatives(e ProducerExecution, w generated.NativeReplacementRecoveryWitness, o generated.NativeObservation) error {
	if e.ReplacementRecovery == nil || e.Plan.HostReplacement == nil || !exactNativeJSON(generated.SchemaIDNativeReplacementRecoveryWitness, w) || len(w.Attempts) != 3 {
		return ErrUnavailable
	}
	positive := e.ReplacementRecovery
	q := e.Plan.HostReplacement
	if w.ReplacementID != q.ReplacementID || w.BindingDigest != positive.Replacement.BindingDigest {
		return ErrUnavailable
	}
	outer, err := time.Parse(time.RFC3339Nano, o.ObservedAt)
	if err != nil {
		return ErrUnavailable
	}
	seen := map[string]bool{}
	var frozenTime, interruptTime, returnTime time.Time
	for _, a := range w.Attempts {
		if seen[a.Kind] || !sameReplacementOwnership(a.Before, a.After) || a.Before.ReplacementID != w.ReplacementID || a.Before.BindingDigest != w.BindingDigest || a.Before.OldHostID != q.OldHostID || a.Before.NewHostID != q.NewHostID || a.Before.OldIdentityDigest != q.OldIdentityDigest || a.Before.NewIdentityDigest != q.NewIdentityDigest || a.Before.RestorationClass != "control-database" || a.Before.FreezeEventDigest == "" || a.Before.FreezeEventDigest != positive.Replacement.FreezeEventDigest {
			return ErrUnavailable
		}
		seen[a.Kind] = true
		at, err := time.Parse(time.RFC3339Nano, a.ObservedAt)
		if err != nil || at.After(outer) {
			return ErrUnavailable
		}
		switch a.Kind {
		case "concurrent-replacement":
			if a.Request == nil || a.Request.Replacement == nil || a.Request.Action != nil || a.Before.Status != "frozen" || a.Before.RecoveryEpoch != positive.Binding.PriorRecoveryEpoch || !frozenAliasesMatch(a.Before, *q) || !finiteResponseMatches(a.Response, "api.v1.host-replacements.create", "PLAN_STALE", "host-replacement") || !finiteResponseMatches(a.CompetingLookup, "api.v1.host-replacements.get", "RESOURCE_NOT_FOUND", "host-replacement") {
				return ErrUnavailable
			}
			request := *a.Request.Replacement
			if request.ReplacementID == w.ReplacementID || request.Operation != "freeze" || request.ExpectedDeclarationRevision != 0 || request.RecoveryEpoch != a.Before.RecoveryEpoch || hostreplacement.ValidateInput(request) != nil {
				return ErrUnavailable
			}
			request.ReplacementID = w.ReplacementID
			if hostreplacement.BindingDigest(request) != w.BindingDigest {
				return ErrUnavailable
			}
			frozenTime = at
		case "interrupted-transition":
			if a.Request != nil || a.Response != nil || a.CompetingLookup != nil || a.Before.Status != "frozen" || a.Before.RecoveryEpoch != positive.Binding.PriorRecoveryEpoch || !frozenAliasesMatch(a.Before, *q) || !actualRecoveryRestart(a) {
				return ErrUnavailable
			}
			interruptTime = at
		case "old-host-return":
			if a.Request == nil || a.Request.Action == nil || a.Request.Replacement != nil || a.CompetingLookup != nil || a.Before.Status != "committed" || a.Before.RecoveryEpoch != positive.Binding.NextRecoveryEpoch || !sameReplacementOwnership(a.Before, positive.Replacement) || !finiteResponseMatches(a.Response, "api.v1.host-actions.draft", "PREREQUISITE_BLOCKED", "host-action") || !actualRecoveryRestart(a) {
				return ErrUnavailable
			}
			request := a.Request.Action
			if request.ActionID != "debian.baseline.collect" || request.HostID != q.OldHostID || request.ConsoleConfirmation.HostIdentityDigest != q.OldIdentityDigest || request.RecoveryEpoch != a.Before.RecoveryEpoch || hostaction.ValidateRequest(*request) != nil {
				return ErrUnavailable
			}
			returnTime = at
		default:
			return ErrUnavailable
		}
		if a.Request != nil && (a.Request.Kind != a.Kind || a.Request.ReplacementID != w.ReplacementID || a.Request.BindingDigest != w.BindingDigest) {
			return ErrUnavailable
		}
	}
	if len(seen) != 3 || frozenTime.IsZero() || interruptTime.Before(frozenTime) || returnTime.Before(interruptTime) {
		return ErrUnavailable
	}
	return nil
}
func finiteResponseMatches(v *generated.NativeFiniteResponse, command, code, target string) bool {
	return v != nil && exactNativeJSON(generated.SchemaIDNativeFiniteResponse, v) && v.ResponseCommand == command && v.ResponseRequestID != "" && v.ExitCode > 0 && !v.Changed && v.ErrorCode == code && v.ErrorTarget == target
}
func actualRecoveryRestart(a generated.NativeReplacementRecoveryAttempt) bool {
	return a.BeforeBootID != "" && a.AfterBootID != "" && a.BeforeBootID != a.AfterBootID && a.BeforePID > 1 && a.AfterPID > 1 && a.BeforeStartIdentity != "" && a.AfterStartIdentity != "" && a.BeforeStartIdentity != a.AfterStartIdentity
}
func frozenAliasesMatch(s generated.HostReplacementState, q generated.HostReplacementRequest) bool {
	if len(s.AliasBindings) == 0 || len(s.AliasBindings) != len(q.AliasBindings) {
		return false
	}
	for i, a := range s.AliasBindings {
		p := q.AliasBindings[i]
		if a.AliasID != p.AliasID || a.OwnerHostID != q.OldHostID || a.OwnerIdentityDigest != q.OldIdentityDigest || a.OwnerRevision != p.OwnerRevision+1 || a.OwnershipGeneration != p.OwnershipGeneration {
			return false
		}
	}
	return true
}

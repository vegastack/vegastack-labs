package server

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	planengine "github.com/vegastack/vegastack-labs/internal/plan"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/schedule"
	"github.com/vegastack/vegastack-labs/internal/stateexport"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type scheduleObservationReader struct {
	policies     *store.ScheduleRepository
	gates        *store.GateRepository
	declarations *store.DeclarationRepository
	observations *planengine.StateObservationReader
	clock        func() time.Time
}

func (reader scheduleObservationReader) ObserveScheduled(ctx context.Context, binding runengine.ExactStepBinding) (string, error) {
	policyDigest := ""
	for _, extension := range binding.Plan.Extensions {
		if extension.Name == "x-scheduled-policy" {
			policyDigest = extension.ValueDigest
		}
	}
	if reader.policies == nil || policyDigest == "" {
		return "", failure.New(generated.ErrorCodePrerequisiteBlocked, "scheduled-policy", false)
	}
	policy, err := reader.policies.GetActivePolicyByDigest(ctx, policyDigest)
	if err != nil {
		return "", err
	}
	action, err := schedule.BuildAction(policy)
	if err != nil || binding.Step.OperationType != action.OperationType || binding.Step.AdapterID != action.AdapterID || len(action.TargetIDs) != 1 || binding.Step.TargetID != action.TargetIDs[0] {
		return "", failure.New(generated.ErrorCodePlanStale, "scheduled-observation-binding", false)
	}
	switch policy.ActionKind {
	case "gate-check":
		if reader.gates == nil || reader.clock == nil {
			return "", failure.New(generated.ErrorCodePrerequisiteBlocked, "scheduled-gates", false)
		}
		now, all := reader.clock().UTC(), make([]any, 0, len(policy.ExactSourceIDs))
		for _, gateID := range policy.ExactSourceIDs {
			evidence, readErr := reader.gates.ListCurrentAppliedGateEvidence(ctx, gateID, policy.ExactSubjectIDs[0])
			if readErr != nil || len(evidence) != 1 {
				return "", failure.New(generated.ErrorCodePrerequisiteBlocked, "scheduled-gate-evidence", false)
			}
			item := evidence[0]
			expires, expiryErr := time.Parse(time.RFC3339, item.ExpiresAt)
			definitionCurrent := false
			for _, definition := range generated.GeneratedGateDefinitions {
				if definition.GateID == gateID && definition.DefinitionVersion == item.DefinitionVersion && definition.EvaluatorVersion == item.EvaluatorVersion {
					definitionCurrent = true
				}
			}
			if expiryErr != nil || !now.Before(expires) || item.ProofClass != "live" || item.RecoveryEpoch != policy.RecoveryEpoch || item.PolicyVersion != policy.PolicyVersion || !definitionCurrent {
				return "", failure.New(generated.ErrorCodePrerequisiteBlocked, "scheduled-gate-evidence", false)
			}
			all = append(all, evidence)
		}
		_, sum, canonicalErr := stateexport.CanonicalJSON(all)
		if canonicalErr != nil {
			return "", canonicalErr
		}
		return "sha256:" + hex.EncodeToString(sum[:]), nil
	case "observation-refresh":
		if reader.declarations == nil || reader.observations == nil {
			return "", failure.New(generated.ErrorCodePrerequisiteBlocked, "scheduled-observation-reader", false)
		}
		declaration, readErr := reader.declarations.GetRevision(ctx, policy.DeclarationID, policy.DeclarationRevision)
		if readErr != nil || declaration.RecoveryEpoch != policy.RecoveryEpoch {
			return "", failure.New(generated.ErrorCodePlanStale, "scheduled-declaration", false)
		}
		if len(declaration.Operations) != 1 || declaration.Operations[0].TargetID != policy.ExactTargetIDs[0] {
			return "", failure.New(generated.ErrorCodeAuthorizationDenied, "scheduled-observation-target", false)
		}
		return reader.observations.CurrentFingerprint(ctx, declaration.DeclarationID, declaration.Operations)
	default:
		return "", failure.New(generated.ErrorCodeAuthorizationDenied, "scheduled-observation", false)
	}
}

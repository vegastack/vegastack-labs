package run

import (
	"context"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

const OffsiteRetirementAdapterID = "r2.retention"

// OffsiteRetirementExecution is supplied only by a site-qualified composition
// that owns the exact intent, write-ahead journal, two distinct JIT identities,
// provider clients, and survivor verifier.
type OffsiteRetirementExecution interface {
	RetireOffsite(context.Context, adapter.Operation, adapter.ExactExecutionBinding, *credentialref.Value, *credentialref.Value) (string, error)
	VerifiedReceiptExists(context.Context, string, string) (bool, error)
}
type OffsiteRetirementEffect struct{ execution OffsiteRetirementExecution }

func NewOffsiteRetirementEffect(v OffsiteRetirementExecution) (*OffsiteRetirementEffect, error) {
	if v == nil {
		return nil, runError(generated.ErrorCodePrerequisiteBlocked, "offsite-retirement-execution")
	}
	return &OffsiteRetirementEffect{v}, nil
}
func (*OffsiteRetirementEffect) Execute(context.Context, adapter.Operation) (adapter.Effect, error) {
	return adapter.Effect{}, runError(generated.ErrorCodeAuthorizationDenied, "offsite-retirement-bound-credentials")
}
func (e *OffsiteRetirementEffect) ExecuteBoundWithCredentials(ctx context.Context, operation adapter.Operation, binding adapter.ExactExecutionBinding, values []*credentialref.Value) (adapter.Effect, error) {
	if e == nil || e.execution == nil || adapter.ValidateOperation(operation) != nil || operation.AdapterID != OffsiteRetirementAdapterID || operation.OperationType != "backup.retire.offsite" || operation.Idempotent || len(operation.SecretReferences) != 2 || len(values) != 2 || operation.SecretReferences[0].ID == operation.SecretReferences[1].ID || values[0] == nil || values[1] == nil || len(values[0].Bytes()) == 0 || len(values[1].Bytes()) == 0 || binding.PlanID == "" || binding.RunID == "" || binding.StepID == "" || binding.LeaseID == "" {
		return adapter.Effect{}, runError(generated.ErrorCodePrerequisiteBlocked, "offsite-retirement-binding")
	}
	deadline, err := time.Parse(time.RFC3339, binding.MaximumExpiresAt)
	if err != nil || !time.Now().UTC().Before(deadline) || !exactOffsiteRetirementExtensions(binding.ContractExtensions, operation.ArtifactDigest) {
		return adapter.Effect{}, runError(generated.ErrorCodePlanStale, "offsite-retirement-binding")
	}
	digest, err := e.execution.RetireOffsite(ctx, operation, binding, values[0], values[1])
	if err != nil {
		return adapter.Effect{EffectObserved: true}, err
	}
	if digest == "" {
		return adapter.Effect{EffectObserved: true}, runError(generated.ErrorCodeIntegrityFailure, "offsite-retirement-receipt")
	}
	return adapter.Effect{Status: "succeeded", ResultDigest: digest, Changed: true, EffectObserved: true}, nil
}
func (e *OffsiteRetirementEffect) Verify(ctx context.Context, operation adapter.Operation, result adapter.Effect) (adapter.Verification, error) {
	if e == nil || e.execution == nil || adapter.ValidateEffect(result) != nil || operation.TargetID == "" || result.Status != "succeeded" {
		return adapter.Verification{}, runError(generated.ErrorCodeIntegrityFailure, "offsite-retirement-effect")
	}
	ok, err := e.execution.VerifiedReceiptExists(ctx, operation.TargetID, result.ResultDigest)
	if err != nil {
		return adapter.Verification{}, err
	}
	return adapter.Verification{Verified: ok, Digest: result.ResultDigest}, nil
}
func exactOffsiteRetirementExtensions(values []generated.ContractExtension, digest string) bool {
	seenIntent, seenCredential := false, false
	for _, v := range values {
		switch v.Name {
		case "x-backup-offsite-retirement":
			if seenIntent || v.ValueDigest != digest {
				return false
			}
			seenIntent = true
		case "x-credential-bindings":
			if seenCredential || v.ValueDigest == "" {
				return false
			}
			seenCredential = true
		default:
			return false
		}
	}
	return seenIntent && seenCredential
}

var _ adapter.Adapter = (*OffsiteRetirementEffect)(nil)
var _ adapter.BoundCredentialExecutor = (*OffsiteRetirementEffect)(nil)

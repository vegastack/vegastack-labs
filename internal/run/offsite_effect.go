package run

import (
	"context"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/backup"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

const OffsiteAdapterID = "labs.r2-offsite"

// OffsiteExecution is the fully composed, site-qualified copy/verification
// boundary. Production supplies it only after G-008 has qualified the actual
// rule, signer, read path, custody host, and recovery key.
type OffsiteExecution interface {
	ExecuteOffsite(context.Context, adapter.Operation, adapter.ExactExecutionBinding, *credentialref.Value) (backup.OffsiteProof, error)
	ProofExists(context.Context, string, string) (bool, error)
}

type OffsiteCopyRunner interface {
	CopyAndVerify(context.Context, adapter.Operation, adapter.ExactExecutionBinding, *credentialref.Value) (backup.OffsiteProof, error)
}

type OffsiteProofCatalog interface {
	ProofExists(context.Context, string, string) (bool, error)
}

// CatalogOffsiteExecution is the concrete composition seam: a qualified site
// supplies the real copy/verify runner, while durable proof lookup is always
// the server-owned catalog. With either side absent the adapter cannot exist.
type CatalogOffsiteExecution struct {
	runner  OffsiteCopyRunner
	catalog OffsiteProofCatalog
}

func NewCatalogOffsiteExecution(runner OffsiteCopyRunner, catalog OffsiteProofCatalog) (*CatalogOffsiteExecution, error) {
	if runner == nil || catalog == nil {
		return nil, runError(generated.ErrorCodePrerequisiteBlocked, "offsite-execution")
	}
	return &CatalogOffsiteExecution{runner: runner, catalog: catalog}, nil
}

func (execution *CatalogOffsiteExecution) ExecuteOffsite(ctx context.Context, operation adapter.Operation, binding adapter.ExactExecutionBinding, parent *credentialref.Value) (backup.OffsiteProof, error) {
	return execution.runner.CopyAndVerify(ctx, operation, binding, parent)
}

func (execution *CatalogOffsiteExecution) ProofExists(ctx context.Context, generationID, proofDigest string) (bool, error) {
	return execution.catalog.ProofExists(ctx, generationID, proofDigest)
}

type OffsiteEffect struct {
	execution OffsiteExecution
}

func NewOffsiteEffect(execution OffsiteExecution) (*OffsiteEffect, error) {
	if execution == nil {
		return nil, runError(generated.ErrorCodePrerequisiteBlocked, "offsite-adapter")
	}
	return &OffsiteEffect{execution: execution}, nil
}

// Execute denies the unbound adapter path. Off-site copy always consumes the
// exact borrowed parent signing reference through BoundCredentialExecutor.
func (*OffsiteEffect) Execute(context.Context, adapter.Operation) (adapter.Effect, error) {
	return adapter.Effect{}, runError(generated.ErrorCodeAuthorizationDenied, "offsite-bound-credential")
}

func (effect *OffsiteEffect) ExecuteBoundWithCredentials(ctx context.Context, operation adapter.Operation, binding adapter.ExactExecutionBinding, values []*credentialref.Value) (adapter.Effect, error) {
	if effect == nil || effect.execution == nil || adapter.ValidateOperation(operation) != nil || operation.AdapterID != OffsiteAdapterID || operation.OperationType != "backup.offsite.copy" || operation.Idempotent ||
		len(operation.SecretReferences) != 1 || len(values) != 1 || values[0] == nil || len(values[0].Bytes()) == 0 ||
		binding.PlanID == "" || binding.PlanDigest == "" || binding.RunID == "" || binding.StepID == "" || binding.LeaseID == "" || binding.StateRevision < 0 || binding.RecoveryEpoch < 0 {
		return adapter.Effect{}, runError(generated.ErrorCodePrerequisiteBlocked, "offsite-exact-binding")
	}
	deadline, err := time.Parse(time.RFC3339, binding.MaximumExpiresAt)
	if err != nil || !time.Now().UTC().Before(deadline) || !hasExactOffsiteExtensions(binding.ContractExtensions, operation.ArtifactDigest) {
		return adapter.Effect{}, runError(generated.ErrorCodePrerequisiteBlocked, "offsite-exact-binding")
	}
	proof, err := effect.execution.ExecuteOffsite(ctx, operation, binding, values[0])
	if err != nil {
		return adapter.Effect{}, err
	}
	if proof.Status != backup.OffsiteStatusVerified || proof.ProofClass != backup.OffsiteProofQualified || proof.ProofDigest == "" || proof.GenerationID != operation.TargetID || proof.RecoveryEpoch != binding.RecoveryEpoch {
		return adapter.Effect{EffectObserved: true}, runError(generated.ErrorCodeIntegrityFailure, "offsite-proof")
	}
	exists, err := effect.execution.ProofExists(ctx, proof.GenerationID, proof.ProofDigest)
	if err != nil {
		return adapter.Effect{EffectObserved: true}, err
	}
	if !exists {
		return adapter.Effect{EffectObserved: true}, runError(generated.ErrorCodeIntegrityFailure, "offsite-proof")
	}
	generationID := proof.GenerationID
	return adapter.Effect{Status: "succeeded", ResultDigest: proof.ProofDigest, PendingPointID: &generationID, Changed: true, EffectObserved: true}, nil
}

func (effect *OffsiteEffect) Verify(ctx context.Context, operation adapter.Operation, result adapter.Effect) (adapter.Verification, error) {
	if effect == nil || effect.execution == nil || adapter.ValidateOperation(operation) != nil || operation.AdapterID != OffsiteAdapterID || operation.OperationType != "backup.offsite.copy" ||
		adapter.ValidateEffect(result) != nil || result.Status != "succeeded" || result.PendingPointID == nil || *result.PendingPointID != operation.TargetID {
		return adapter.Verification{}, runError(generated.ErrorCodeIntegrityFailure, "offsite-effect")
	}
	exists, err := effect.execution.ProofExists(ctx, *result.PendingPointID, result.ResultDigest)
	if err != nil {
		return adapter.Verification{}, err
	}
	return adapter.Verification{Verified: exists, Digest: result.ResultDigest}, nil
}

func hasExactOffsiteExtensions(extensions []generated.ContractExtension, inputDigest string) bool {
	seenGeneration, seenCredential := false, false
	for _, extension := range extensions {
		switch extension.Name {
		case "x-offsite-generation":
			if seenGeneration || extension.ValueDigest != inputDigest {
				return false
			}
			seenGeneration = true
		case "x-credential-bindings":
			if seenCredential || extension.ValueDigest == "" {
				return false
			}
			seenCredential = true
		default:
			return false
		}
	}
	return seenGeneration && seenCredential
}

var (
	_ adapter.Adapter                 = (*OffsiteEffect)(nil)
	_ adapter.BoundCredentialExecutor = (*OffsiteEffect)(nil)
)

package backup

import (
	"context"
	"errors"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/adapter/r2retention"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type OffsiteRetirementProviderFactory interface {
	Clients(context.Context, store.OffsiteRetirementIntent, *credentialref.Value, *credentialref.Value) (r2retention.RuleClient, r2retention.ObjectClient, OffsiteSurvivorVerifier, error)
}

// SQLRetirementExecution is the production destructive composition. It owns
// the exact SQL intent/lease/journal/receipt lifecycle and permits provider
// calls only through clients built from the two bound one-run credentials.
type SQLRetirementExecution struct {
	repository *store.OffsiteRetirementRepository
	providers  OffsiteRetirementProviderFactory
	clock      func() time.Time
}

func NewSQLRetirementExecution(authority *store.Store, providers OffsiteRetirementProviderFactory, clock func() time.Time) (*SQLRetirementExecution, error) {
	if authority == nil || providers == nil {
		return nil, errors.New("offsite retirement execution unavailable")
	}
	if clock == nil {
		clock = time.Now
	}
	return &SQLRetirementExecution{repository: store.NewOffsiteRetirementRepository(authority), providers: providers, clock: clock}, nil
}

func (execution *SQLRetirementExecution) RetireOffsite(ctx context.Context, operation adapter.Operation, binding adapter.ExactExecutionBinding, lockAdmin, retention *credentialref.Value) (string, error) {
	if execution == nil || execution.repository == nil || execution.providers == nil || lockAdmin == nil || retention == nil || operation.ArtifactDigest == "" {
		return "", errors.New("offsite retirement execution unavailable")
	}
	intent, err := execution.repository.GetOffsiteRetirementIntentByDigest(ctx, operation.ArtifactDigest)
	if err != nil || intent.PlanID != binding.PlanID || intent.PlanDigest != binding.PlanDigest || intent.GenerationID != operation.TargetID || intent.StateRevision != binding.StateRevision || intent.RecoveryEpoch != binding.RecoveryEpoch || intent.CredentialBindingDigest != operation.InputDigest ||
		len(operation.SecretReferences) != 2 || operation.SecretReferences[0].Consumer != intent.LockAdminReferenceID || operation.SecretReferences[1].Consumer != intent.RetentionReferenceID || operation.SecretReferences[0].ID == operation.SecretReferences[1].ID {
		return "", errors.New("offsite retirement intent binding invalid")
	}
	deadline, err := time.Parse(time.RFC3339, binding.MaximumExpiresAt)
	if err != nil || !execution.clock().UTC().Before(deadline) {
		return "", errors.New("offsite retirement deadline invalid")
	}
	lease, err := execution.repository.ClaimOffsiteRetirement(ctx, store.OffsiteRetirementClaim{IntentID: intent.IntentID, LeaseID: "retirement-" + binding.LeaseID, RunID: binding.RunID, StepID: binding.StepID, ExecutorLeaseID: binding.LeaseID, MaximumExpiresAt: deadline})
	if err != nil {
		return "", err
	}
	rules, objects, verifier, err := execution.providers.Clients(ctx, intent, lockAdmin, retention)
	if err != nil {
		return "", err
	}
	defer closeRetirementClient(rules)
	defer closeRetirementClient(objects)
	defer closeRetirementClient(verifier)
	if verifier == nil {
		return "", errors.New("fresh offsite survivor verifier unavailable")
	}
	journal, err := r2retention.RetireExact(ctx, intent, lease, rules, objects, execution.repository)
	if err != nil {
		return "", err
	}
	if journal.Status != "effects-observed" {
		return "", errors.New("offsite retirement effects unresolved")
	}
	verifiedAt := execution.clock().UTC()
	proof, err := VerifyOffsiteRetirement(ctx, intent, journal, execution.repository, verifier, verifiedAt)
	if err != nil {
		return "", err
	}
	survivors := make([]store.OffsiteRetirementSurvivorSettlement, len(proof.Survivors))
	for index, value := range proof.Survivors {
		survivors[index] = store.OffsiteRetirementSurvivorSettlement{PointID: value.PointID, GenerationID: value.GenerationID, RuleDigest: value.RuleDigest, InventoryDigest: value.InventoryDigest, FullReadDigest: value.FullReadDigest, RestoreDigest: value.RestoreDigest, RecoveryEpoch: value.RecoveryEpoch, ObservedAt: value.ObservedAt}
	}
	receipt, err := execution.repository.SettleVerifiedReceipt(ctx, store.OffsiteRetirementVerifiedSettlement{ReceiptID: "receipt-" + lease.LeaseID, IntentID: intent.IntentID, LeaseID: lease.LeaseID, ReclaimedBytes: journal.ReclaimedBytes, Survivors: survivors})
	if err != nil {
		return "", err
	}
	return receipt.EffectDigest, nil
}

func closeRetirementClient(value any) {
	if closer, ok := value.(interface{ Close() error }); ok && closer != nil {
		_ = closer.Close()
	}
}

func (execution *SQLRetirementExecution) VerifiedReceiptExists(ctx context.Context, generationID, digest string) (bool, error) {
	if execution == nil || execution.repository == nil {
		return false, errors.New("offsite retirement execution unavailable")
	}
	return execution.repository.VerifiedReceiptExists(ctx, generationID, digest)
}

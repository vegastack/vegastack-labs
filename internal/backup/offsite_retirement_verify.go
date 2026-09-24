package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter/r2retention"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type OffsiteSurvivorProof struct {
	PointID, GenerationID, RuleDigest, InventoryDigest, FullReadDigest, RestoreDigest string
	FullReadAt, RestoredAt, ObservedAt                                                time.Time
	RecoveryEpoch                                                                     int64
}
type OffsiteSurvivorVerifier interface {
	VerifyOffsiteSurvivor(context.Context, string) (OffsiteSurvivorProof, error)
}

// OffsiteRetirementSettlementCatalog is a durable #114 catalog view. The
// verifier cannot settle against caller-authored digest-shaped values.
type OffsiteRetirementSettlementCatalog interface {
	ExpectedOffsiteSurvivor(context.Context, string) (store.OffsiteRetirementSurvivorSettlement, error)
	CurrentOffsiteLastGood(context.Context, int64) (string, error)
}
type OffsiteRetirementProof struct {
	IntentID, GenerationID, EffectDigest, SurvivorProofDigest string
	Survivors                                                 []OffsiteSurvivorProof
	ReclaimedBytes, RecoveryEpoch                             int64
	VerifiedAt                                                time.Time
}

func VerifyOffsiteRetirement(ctx context.Context, intent store.OffsiteRetirementIntent, effect r2retention.EffectJournal, catalog OffsiteRetirementSettlementCatalog, verifier OffsiteSurvivorVerifier, now time.Time) (OffsiteRetirementProof, error) {
	if catalog == nil || verifier == nil || now.IsZero() || effect.Status != "effects-observed" || effect.PostRuleDigest != intent.SurvivorRuleDigest || effect.ObjectInventoryDigest != digestStoreObjects(intent.Objects) || int64(len(effect.DeletedKeys)) != intent.MaxWorkObjects || effect.ReclaimedBytes != intent.MaxMutationBytes || len(intent.SurvivorPointIDs) == 0 {
		return OffsiteRetirementProof{}, errors.New("offsite retirement effect is not settled")
	}
	expectedKeys := make([]string, len(intent.Objects))
	for i, v := range intent.Objects {
		expectedKeys[i] = v.Key
	}
	slices.Sort(expectedKeys)
	actualKeys := append([]string(nil), effect.DeletedKeys...)
	slices.Sort(actualKeys)
	if !slices.Equal(expectedKeys, actualKeys) {
		return OffsiteRetirementProof{}, errors.New("offsite retirement key set differs")
	}
	proofs := make([]OffsiteSurvivorProof, 0, len(intent.SurvivorPointIDs))
	seen := map[string]bool{}
	lastGood, err := catalog.CurrentOffsiteLastGood(ctx, intent.RecoveryEpoch)
	if err != nil || lastGood == "" {
		return OffsiteRetirementProof{}, errors.New("offsite last-good catalog unavailable")
	}
	for _, id := range intent.SurvivorPointIDs {
		if seen[id] {
			return OffsiteRetirementProof{}, errors.New("duplicate survivor")
		}
		seen[id] = true
		expected, err := catalog.ExpectedOffsiteSurvivor(ctx, id)
		if err != nil {
			return OffsiteRetirementProof{}, errors.New("offsite survivor catalog failed")
		}
		p, err := verifier.VerifyOffsiteSurvivor(ctx, id)
		if err != nil || p.PointID != id || p.GenerationID == intent.GenerationID || p.RecoveryEpoch != intent.RecoveryEpoch || p.FullReadAt.IsZero() || p.RestoredAt.IsZero() || p.ObservedAt.IsZero() || p.FullReadAt.After(p.ObservedAt) || p.RestoredAt.After(p.ObservedAt) || p.FullReadAt.Before(now) || p.RestoredAt.Before(now) || p.ObservedAt.Before(now) ||
			expected.PointID != id || expected.GenerationID != p.GenerationID || expected.RecoveryEpoch != p.RecoveryEpoch || expected.RuleDigest != p.RuleDigest || expected.InventoryDigest != p.InventoryDigest || p.FullReadDigest == expected.FullReadDigest || p.RestoreDigest == expected.RestoreDigest {
			return OffsiteRetirementProof{}, errors.New("offsite survivor proof failed")
		}
		proofs = append(proofs, p)
	}
	if !seen[lastGood] {
		return OffsiteRetirementProof{}, errors.New("current offsite last-good is not a survivor")
	}
	slices.SortFunc(proofs, func(a, b OffsiteSurvivorProof) int {
		if a.PointID < b.PointID {
			return -1
		}
		if a.PointID > b.PointID {
			return 1
		}
		return 0
	})
	body, _ := json.Marshal(struct {
		Effect r2retention.EffectJournal
		Proofs []OffsiteSurvivorProof
	}{effect, proofs})
	sum := sha256.Sum256(append([]byte("offsite-retirement-proof-v1\x00"), body...))
	proofDigest := "sha256:" + hex.EncodeToString(sum[:])
	return OffsiteRetirementProof{IntentID: intent.IntentID, GenerationID: intent.GenerationID, EffectDigest: proofDigest, SurvivorProofDigest: proofDigest, Survivors: proofs, ReclaimedBytes: effect.ReclaimedBytes, RecoveryEpoch: intent.RecoveryEpoch, VerifiedAt: now}, nil
}

func digestStoreObjects(values []store.OffsiteRetirementObject) string {
	objects := make([]r2retention.Object, len(values))
	for i, v := range values {
		objects[i] = r2retention.Object{Key: v.Key, Digest: v.Digest, Bytes: v.Bytes}
	}
	return r2retention.DigestObjects(objects)
}

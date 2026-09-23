package backup

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter/r2retention"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type survivorVerifierFixture struct {
	fail string
	now  time.Time
}

func (v survivorVerifierFixture) ExpectedOffsiteSurvivor(_ context.Context, id string) (store.OffsiteRetirementSurvivorSettlement, error) {
	d := "sha256:" + strings.Repeat("a", 64)
	return store.OffsiteRetirementSurvivorSettlement{PointID: id, GenerationID: "survivor-" + id, RuleDigest: d, InventoryDigest: d, FullReadDigest: d, RestoreDigest: d, RecoveryEpoch: 2}, nil
}
func (v survivorVerifierFixture) CurrentOffsiteLastGood(context.Context, int64) (string, error) {
	return "point-good", nil
}

func (v survivorVerifierFixture) VerifyOffsiteSurvivor(_ context.Context, id string) (OffsiteSurvivorProof, error) {
	if id == v.fail {
		return OffsiteSurvivorProof{}, errors.New("restore failed")
	}
	d := "sha256:" + strings.Repeat("a", 64)
	return OffsiteSurvivorProof{PointID: id, GenerationID: "survivor-" + id, RuleDigest: d, InventoryDigest: d, FullReadDigest: "sha256:" + strings.Repeat("b", 64), RestoreDigest: "sha256:" + strings.Repeat("c", 64), FullReadAt: v.now, RestoredAt: v.now, ObservedAt: v.now, RecoveryEpoch: 2}, nil
}

func TestOffsiteRetirementCannotSettleAfterPartialDeleteOrFailedSurvivor(t *testing.T) {
	now := time.Date(2026, 9, 24, 1, 0, 0, 0, time.UTC)
	d := "sha256:" + strings.Repeat("a", 64)
	objects := []store.OffsiteRetirementObject{{Key: "data/a", Digest: d, Bytes: 8}}
	intent := store.OffsiteRetirementIntent{IntentID: "intent-a", GenerationID: "target-generation", InventoryDigest: d, SurvivorRuleDigest: d, Objects: objects, SurvivorPointIDs: []string{"point-good"}, RecoveryEpoch: 2, MaxWorkObjects: 1, MaxMutationBytes: 8}
	effect := r2retention.EffectJournal{Status: "uncertain", PostRuleDigest: d, ObjectInventoryDigest: r2retention.DigestObjects([]r2retention.Object{{Key: "data/a", Digest: d, Bytes: 8}}), DeletedKeys: []string{"data/a"}, ReclaimedBytes: 8}
	fixture := survivorVerifierFixture{now: now}
	if _, err := VerifyOffsiteRetirement(context.Background(), intent, effect, fixture, fixture, now); err == nil {
		t.Fatal("partial effect settled")
	}
	effect.Status = "effects-observed"
	failed := survivorVerifierFixture{fail: "point-good", now: now}
	if _, err := VerifyOffsiteRetirement(context.Background(), intent, effect, failed, failed, now); err == nil {
		t.Fatal("failed survivor settled")
	}
	proof, err := VerifyOffsiteRetirement(context.Background(), intent, effect, fixture, fixture, now)
	if err != nil || proof.ReclaimedBytes != 8 || len(proof.Survivors) != 1 {
		t.Fatalf("verified proof=%+v err=%v", proof, err)
	}
}

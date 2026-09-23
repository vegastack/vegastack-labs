package backup

import (
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/adapter/r2retention"
)

func retirementGeneration(id, point string, now time.Time) PendingOffsiteGeneration {
	digest := "sha256:" + strings.Repeat("a", 64)
	object := OffsiteObject{Key: "data/a", Digest: digest, Bytes: 10}
	base := "backups/" + id + "/"
	rules := []adapter.RetentionRule{{RuleID: id + "-config", Prefix: base + "config"}, {RuleID: id + "-keys", Prefix: base + "keys/"}, {RuleID: id + "-data", Prefix: base + "data/"}, {RuleID: id + "-index", Prefix: base + "index/"}, {RuleID: id + "-snapshots", Prefix: base + "snapshots/"}}
	return PendingOffsiteGeneration{SourcePointID: point, SourceSnapshotID: strings.Repeat("b", 64), SourceManifestDigest: digest, SourceInventoryDigest: digest, SourceContentDigest: digest, SourceDependencyDigest: digest, SourceResticDigest: digest, KeyReferenceID: "key-a", GenerationID: id, RepositoryID: strings.Repeat("d", 64), OffsiteSnapshotID: strings.Repeat("c", 64), OffsiteInventoryDigest: DigestOffsiteInventory([]OffsiteObject{object}), RuleDigest: digest, ProtectedRules: rules, Objects: []OffsiteObject{object}, SessionExpiries: []time.Time{now.Add(-2 * time.Hour)}, SourceRevision: 2, StateRevision: 4, RecoveryEpoch: 3, ObjectCount: 1, ObjectBytes: 10, IssuanceStoppedAt: now.Add(-3 * time.Hour)}
}

func TestOffsiteSelectionPreservesSoleLastGoodAndExactFiveRules(t *testing.T) {
	now := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
	old := retirementGeneration("generation-old", "point-old", now)
	good := retirementGeneration("generation-good", "point-good", now)
	local := RetirementSelection{Targets: []RetirementCandidate{{PointID: "point-old"}}, Survivors: []RetirementCandidate{{PointID: "point-good"}}, RecoveryEpoch: 3}
	catalog := OffsiteRetirementCatalog{Generations: []PendingOffsiteGeneration{old}, GenerationCreatedAt: map[string]time.Time{"generation-old": now.Add(-30 * 24 * time.Hour)}, CurrentRules: ruleRefs(old), VerifiedPointIDs: []string{"point-old"}, LastGoodPointIDs: []string{"point-old"}, BucketID: "bucket-a", CatalogDigest: "sha256:" + strings.Repeat("e", 64), RuleCount: 5, RuleLimit: 1000, TotalBytes: 1000, AvailableBytes: 900, ObservedAt: now}
	catalog.RuleSetDigest = retirementRuleDigest(catalog.CurrentRules)
	if _, err := SelectOffsiteRetirement(catalog, local, now); err == nil {
		t.Fatal("sole last good selected")
	}
	catalog.Generations = []PendingOffsiteGeneration{old, good}
	catalog.GenerationCreatedAt["generation-good"] = now.Add(-time.Hour)
	catalog.CurrentRules = append(ruleRefs(old), ruleRefs(good)...)
	catalog.RuleSetDigest = retirementRuleDigest(catalog.CurrentRules)
	catalog.VerifiedPointIDs = []string{"point-old", "point-good"}
	catalog.LastGoodPointIDs = []string{"point-good"}
	catalog.RuleCount = 10
	broken := catalog
	broken.Generations = append([]PendingOffsiteGeneration(nil), catalog.Generations...)
	broken.Generations[0].ProtectedRules = broken.Generations[0].ProtectedRules[:4]
	if _, err := SelectOffsiteRetirement(broken, local, now); err == nil {
		t.Fatal("incomplete rule ownership selected")
	}
	candidate, err := SelectOffsiteRetirement(catalog, local, now)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.GenerationID != "generation-old" || len(candidate.Rules) != 5 || len(candidate.Objects) != 1 || len(candidate.SurvivorPointIDs) != 1 {
		t.Fatalf("candidate not exact: %+v", candidate)
	}
}

func retirementRuleDigest(rules []RetentionRuleRef) string {
	values := make([]r2retention.Rule, len(rules))
	for i, v := range rules {
		values[i] = r2retention.Rule{RuleID: v.RuleID, Prefix: v.Prefix}
	}
	return r2retention.DigestRuleSet(r2retention.RuleSet{Rules: values})
}

func ruleRefs(values ...PendingOffsiteGeneration) []RetentionRuleRef {
	var out []RetentionRuleRef
	for _, value := range values {
		for _, rule := range value.ProtectedRules {
			out = append(out, RetentionRuleRef{RuleID: rule.RuleID, Prefix: rule.Prefix})
		}
	}
	return out
}

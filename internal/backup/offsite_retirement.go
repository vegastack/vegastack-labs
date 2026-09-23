package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"time"
)

const OffsiteRetentionWindow = 14 * 24 * time.Hour

// OffsiteRetirementCatalog is a complete, current view used only to construct
// an inert exact retirement proposal. Mutation authority is deliberately not
// part of this type.
type OffsiteRetirementCatalog struct {
	Generations                                     []PendingOffsiteGeneration
	VerifiedPointIDs                                []string
	LastGoodPointIDs                                []string
	DependencyPointIDs                              []string
	ActivePromisePointIDs                           []string
	BucketID, RuleSetDigest, CatalogDigest          string
	RuleCount, RuleLimit                            int
	TotalBytes, AvailableBytes, ExpectedGrowthBytes int64
	ObservedAt                                      time.Time
}

type OffsiteRetirementCandidate struct {
	GenerationID, PointID, BucketID, RuleSetDigest, SurvivorRuleDigest            string
	ManifestDigest, CatalogDigest, InventoryDigest                                string
	Rules                                                                         []RetentionRuleRef
	Objects                                                                       []OffsiteObject
	SurvivorPointIDs                                                              []string
	RecoveryEpoch, SourceRevision                                                 int64
	ExpectedRetainedBytes, ExpectedReclaimBytes, MaxWorkObjects, MaxMutationBytes int64
	CapacityWarning                                                               bool
}

type RetentionRuleRef struct{ RuleID, Prefix string }

// SelectOffsiteRetirement creates one deterministic proposal and never mutates
// provider or local state. The local target makes off-site retirement follow
// the same human-reviewed retention decision as local retirement.
func SelectOffsiteRetirement(catalog OffsiteRetirementCatalog, local RetirementSelection, now time.Time) (OffsiteRetirementCandidate, error) {
	fail := func() (OffsiteRetirementCandidate, error) {
		return OffsiteRetirementCandidate{}, errors.New("offsite retirement prerequisite blocked")
	}
	if now.IsZero() || catalog.ObservedAt.IsZero() || catalog.ObservedAt.After(now) || catalog.BucketID == "" ||
		!validBackupManifestDigest(catalog.RuleSetDigest) || !validBackupManifestDigest(catalog.CatalogDigest) ||
		catalog.RuleLimit <= 0 || catalog.RuleLimit > 1000 || catalog.RuleCount < 0 || catalog.RuleCount > catalog.RuleLimit ||
		catalog.TotalBytes <= 0 || catalog.AvailableBytes < 0 || catalog.AvailableBytes > catalog.TotalBytes || local.RecoveryEpoch < 0 {
		return fail()
	}
	verified := stringSet(catalog.VerifiedPointIDs)
	lastGood := stringSet(catalog.LastGoodPointIDs)
	dependencies := stringSet(catalog.DependencyPointIDs)
	promises := stringSet(catalog.ActivePromisePointIDs)
	if len(lastGood) == 0 || len(catalog.Generations) < 2 {
		return fail()
	}
	targets := stringSet(nil)
	for _, target := range local.Targets {
		targets[target.PointID] = true
	}
	var chosen *PendingOffsiteGeneration
	survivors := make([]string, 0, len(catalog.Generations)-1)
	var retained int64
	for i := range catalog.Generations {
		generation := catalog.Generations[i]
		if ValidatePendingOffsiteGeneration(generation) != nil || generation.RecoveryEpoch != local.RecoveryEpoch || !verified[generation.SourcePointID] {
			return fail()
		}
		eligible := targets[generation.SourcePointID] && !lastGood[generation.SourcePointID] && !dependencies[generation.SourcePointID] && !promises[generation.SourcePointID]
		if eligible && chosen == nil {
			copy := generation
			chosen = &copy
			continue
		}
		survivors = append(survivors, generation.SourcePointID)
		if generation.ObjectBytes > catalog.TotalBytes-retained {
			return fail()
		}
		retained += generation.ObjectBytes
	}
	if chosen == nil || len(survivors) == 0 || len(chosen.ProtectedRules) != 5 || chosen.IssuanceStoppedAt.After(now) {
		return fail()
	}
	for _, expiry := range chosen.SessionExpiries {
		if expiry.After(now) {
			return fail()
		}
	}
	// A retirement may not be used to manufacture capacity. The remaining
	// retained bytes plus expected growth must still fit with 30% headroom.
	projected := retained + catalog.ExpectedGrowthBytes
	limit := catalog.TotalBytes * 7 / 10
	if projected < 0 || projected > limit {
		return fail()
	}
	rules := make([]RetentionRuleRef, len(chosen.ProtectedRules))
	for i, rule := range chosen.ProtectedRules {
		rules[i] = RetentionRuleRef{rule.RuleID, rule.Prefix}
	}
	slices.SortFunc(rules, func(a, b RetentionRuleRef) int {
		if a.RuleID < b.RuleID {
			return -1
		}
		if a.RuleID > b.RuleID {
			return 1
		}
		return 0
	})
	objects := append([]OffsiteObject(nil), chosen.Objects...)
	slices.SortFunc(objects, func(a, b OffsiteObject) int {
		if a.Key < b.Key {
			return -1
		}
		if a.Key > b.Key {
			return 1
		}
		return 0
	})
	slices.Sort(survivors)
	survivorBody, _ := json.Marshal(allSurvivorRules(catalog.Generations, chosen.GenerationID))
	hash := sha256.New()
	_, _ = hash.Write([]byte("rules"))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(survivorBody)
	_, _ = hash.Write([]byte{0})
	digest := hash.Sum(nil)
	return OffsiteRetirementCandidate{
		GenerationID: chosen.GenerationID, PointID: chosen.SourcePointID, BucketID: catalog.BucketID,
		RuleSetDigest: catalog.RuleSetDigest, SurvivorRuleDigest: "sha256:" + hex.EncodeToString(digest),
		ManifestDigest: chosen.SourceManifestDigest, CatalogDigest: catalog.CatalogDigest, InventoryDigest: chosen.OffsiteInventoryDigest,
		Rules: rules, Objects: objects, SurvivorPointIDs: survivors, RecoveryEpoch: chosen.RecoveryEpoch, SourceRevision: chosen.SourceRevision,
		ExpectedRetainedBytes: retained, ExpectedReclaimBytes: chosen.ObjectBytes, MaxWorkObjects: int64(len(objects)), MaxMutationBytes: chosen.ObjectBytes,
		CapacityWarning: catalog.TotalBytes-catalog.AvailableBytes >= catalog.TotalBytes*7/10,
	}, nil
}

func stringSet(values []string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		if value != "" {
			result[value] = true
		}
	}
	return result
}
func allSurvivorRules(generations []PendingOffsiteGeneration, excluded string) []RetentionRuleRef {
	var rules []RetentionRuleRef
	for _, generation := range generations {
		if generation.GenerationID != excluded {
			for _, rule := range generation.ProtectedRules {
				rules = append(rules, RetentionRuleRef{rule.RuleID, rule.Prefix})
			}
		}
	}
	slices.SortFunc(rules, func(a, b RetentionRuleRef) int {
		if a.RuleID < b.RuleID {
			return -1
		}
		if a.RuleID > b.RuleID {
			return 1
		}
		return 0
	})
	return rules
}

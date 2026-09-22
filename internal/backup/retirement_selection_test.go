package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func retirementCandidate(id string, day int, proof bool) RetirementCandidate {
	digest := "sha256:" + strings.Repeat("a", 64)
	snapshot := sha256.Sum256([]byte(id))
	result := RetirementCandidate{PointID: id, SnapshotID: hex.EncodeToString(snapshot[:]), RepositoryID: "local-standard", ManifestDigest: digest, DependencyDigest: digest, InventoryDigest: digest, CreatedAt: time.Date(2026, 9, day, 0, 0, 0, 0, time.UTC), Bytes: 1024, RecoveryEpoch: 8}
	if proof {
		result.ProofDigest = digest
	}
	return result
}

func TestLocalKeepWithinPreservesOnlyGoodAfterOutage(t *testing.T) {
	catalog := []RetirementCandidate{retirementCandidate("old", 1, false), retirementCandidate("only-good", 10, true), retirementCandidate("rollback-promised", 3, false), retirementCandidate("new-pending", 15, false)}
	catalog[2].ActivePromise = true
	selection, err := SelectLocalRetirement(catalog, []string{"only-good"}, 7*24*time.Hour, 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(selection.Targets) != 1 || selection.Targets[0].PointID != "old" {
		t.Fatalf("unsafe targets: %#v", selection.Targets)
	}
	if len(selection.Survivors) != 3 || selection.ExpectedInventoryDigest == "" {
		t.Fatalf("missing survivors or digest: %#v", selection)
	}
	if len(selection.InertOffsiteGenerationIDs) != 0 {
		t.Fatal("off-site candidate became executable")
	}
}

func TestLocalRetirementRejectsUnqualifiedOrAmbiguousCatalog(t *testing.T) {
	base := []RetirementCandidate{retirementCandidate("good", 10, true), retirementCandidate("old", 1, false)}
	for name, mutate := range map[string]func([]RetirementCandidate) []RetirementCandidate{
		"no-current-good":    func(c []RetirementCandidate) []RetirementCandidate { return c },
		"duplicate-point":    func(c []RetirementCandidate) []RetirementCandidate { return append(c, c[0]) },
		"stale-epoch":        func(c []RetirementCandidate) []RetirementCandidate { c[1].RecoveryEpoch = 7; return c },
		"foreign-repository": func(c []RetirementCandidate) []RetirementCandidate { c[1].RepositoryID = "other"; return c },
		"missing-digest":     func(c []RetirementCandidate) []RetirementCandidate { c[1].InventoryDigest = ""; return c },
		"malformed-snapshot": func(c []RetirementCandidate) []RetirementCandidate { c[1].SnapshotID = "short"; return c },
	} {
		t.Run(name, func(t *testing.T) {
			c := mutate(append([]RetirementCandidate(nil), base...))
			good := []string{"good"}
			if name == "no-current-good" {
				good = []string{"old"}
			}
			if _, err := SelectLocalRetirement(c, good, 7*24*time.Hour, 8); err == nil {
				t.Fatal("unsafe catalog admitted")
			}
		})
	}
}

package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/backupidentity"
	"github.com/vegastack/vegastack-labs/internal/store"
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

func retirementLocks(t *testing.T, pointIDs ...string) store.AppliedLocalRetentionLocks {
	t.Helper()
	catalog := store.LocalRetentionLockCatalog{Schema: "vegastack-labs.dev/local-retention-lock-catalog", SchemaVersion: "1.0.0",
		RepositoryID: backupidentity.StandardRepository, RepositoryClass: "standard", SourceCoverageDigest: store.LocalPromiseSourceCoverageDigest(),
		RecoveryEpoch: 8, Revision: 2, Complete: true, Locks: []store.LocalRetentionLock{}}
	for _, pointID := range pointIDs {
		catalog.Locks = append(catalog.Locks, store.LocalRetentionLock{PointID: pointID, ReasonDigest: "sha256:" + strings.Repeat("a", 64)})
	}
	_, digest, err := store.CanonicalLocalRetentionLockCatalog(catalog)
	if err != nil {
		t.Fatal(err)
	}
	return store.AppliedLocalRetentionLocks{ActivationID: "catalog-applied", CatalogDigest: digest, Sequence: 1, Catalog: catalog}
}

func TestLocalKeepWithinPreservesOnlyGoodAfterOutage(t *testing.T) {
	catalog := []RetirementCandidate{retirementCandidate("old", 1, false), retirementCandidate("only-good", 10, true), retirementCandidate("rollback-promised", 3, false), retirementCandidate("new-pending", 15, false)}
	selection, err := SelectLocalRetirement(catalog, []string{"only-good"}, retirementLocks(t, "rollback-promised"), 7*24*time.Hour, 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(selection.Targets) != 1 || selection.Targets[0].PointID != "old" {
		t.Fatalf("unsafe targets: %#v", selection.Targets)
	}
	if len(selection.Survivors) != 3 || selection.ExpectedInventoryDigest == "" {
		t.Fatalf("missing survivors or digest: %#v", selection)
	}
	if selection.LockCatalogDigest == "" || selection.LockCatalogSequence != 1 {
		t.Fatal("selection lost applied lock catalog binding")
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
		"uppercase-snapshot": func(c []RetirementCandidate) []RetirementCandidate {
			c[1].SnapshotID = strings.Repeat("A", 64)
			return c
		},
		"nonhex-snapshot": func(c []RetirementCandidate) []RetirementCandidate {
			c[1].SnapshotID = strings.Repeat("z", 64)
			return c
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := mutate(append([]RetirementCandidate(nil), base...))
			good := []string{"good"}
			if name == "no-current-good" {
				good = []string{"old"}
			}
			if _, err := SelectLocalRetirement(c, good, retirementLocks(t), 7*24*time.Hour, 8); err == nil {
				t.Fatal("unsafe catalog admitted")
			}
		})
	}
}

func TestLocalRetirementSelectionDeniesMissingOrForgedLocks(t *testing.T) {
	catalog := []RetirementCandidate{retirementCandidate("good", 10, true), retirementCandidate("old", 1, false)}
	if _, err := SelectLocalRetirement(catalog, []string{"good"}, store.AppliedLocalRetentionLocks{}, 7*24*time.Hour, 8); err == nil {
		t.Fatal("missing applied lock catalog admitted")
	}
	forged := retirementLocks(t, "old")
	forged.CatalogDigest = "sha256:" + strings.Repeat("0", 64)
	if _, err := SelectLocalRetirement(catalog, []string{"good"}, forged, 7*24*time.Hour, 8); err == nil {
		t.Fatal("forged lock catalog digest admitted")
	}
	unknown := retirementLocks(t, "other-point")
	if _, err := SelectLocalRetirement(catalog, []string{"good"}, unknown, 7*24*time.Hour, 8); err == nil {
		t.Fatal("unknown promised point admitted")
	}
	selection, err := SelectLocalRetirement(catalog, []string{"good"}, retirementLocks(t, "old"), 7*24*time.Hour, 8)
	if err != nil || len(selection.Targets) != 0 || len(selection.Survivors) != 2 {
		t.Fatalf("locked old point retired: %#v %v", selection, err)
	}
}

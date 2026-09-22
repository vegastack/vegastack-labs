package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

// RetirementCandidate is one point in the complete, current local repository
// catalog. A proof digest is required for any declared last-good survivor.
type RetirementCandidate struct {
	PointID, SnapshotID, RepositoryID                              string
	ManifestDigest, DependencyDigest, InventoryDigest, ProofDigest string
	CreatedAt                                                      time.Time
	Bytes, RecoveryEpoch                                           int64
	ActivePromise                                                  bool
}

// RetirementSelection is an inert, deterministic proposal. Its target list is
// not an execution grant; the exact plan, store intent and retention lease are
// separate human-only steps.
type RetirementSelection struct {
	Targets, Survivors                            []RetirementCandidate
	InertOffsiteGenerationIDs                     []string
	ExpectedInventoryDigest                       string
	MaxWork, MaxRepackBytes, ExpectedReclaimBytes int64
	RecoveryEpoch                                 int64
}

// SelectLocalRetirement measures keep-within relative to the latest verified
// local point. It never retires any current last-good or active recovery promise.
// A missing/ambiguous catalog or unproved last-good fails the whole proposal.
func SelectLocalRetirement(catalog []RetirementCandidate, lastGoodIDs []string, window time.Duration, epoch int64) (RetirementSelection, error) {
	invalid := func() (RetirementSelection, error) {
		return RetirementSelection{}, failure.New(generated.ErrorCodePrerequisiteBlocked, "local-retirement-selection", false)
	}
	if len(catalog) == 0 || len(catalog) > 256 || len(lastGoodIDs) == 0 || len(lastGoodIDs) > len(catalog) || window <= 0 || window > 14*24*time.Hour || epoch < 0 {
		return invalid()
	}
	sorted := append([]RetirementCandidate(nil), catalog...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].PointID < sorted[j].PointID })
	points := make(map[string]RetirementCandidate, len(sorted))
	snapshots := make(map[string]bool, len(sorted))
	repo := sorted[0].RepositoryID
	for _, candidate := range sorted {
		if candidate.PointID == "" || !validObjectName(candidate.SnapshotID) || candidate.RepositoryID == "" || candidate.RepositoryID != repo || candidate.RecoveryEpoch != epoch || candidate.Bytes < 0 || candidate.CreatedAt.IsZero() || !validBackupManifestDigest(candidate.ManifestDigest) || !validBackupManifestDigest(candidate.DependencyDigest) || !validBackupManifestDigest(candidate.InventoryDigest) || (candidate.ProofDigest != "" && !validBackupManifestDigest(candidate.ProofDigest)) || snapshots[candidate.SnapshotID] {
			return invalid()
		}
		if _, duplicate := points[candidate.PointID]; duplicate {
			return invalid()
		}
		points[candidate.PointID] = candidate
		snapshots[candidate.SnapshotID] = true
	}
	good := make(map[string]bool, len(lastGoodIDs))
	var latest time.Time
	for _, id := range lastGoodIDs {
		candidate, ok := points[id]
		if !ok || good[id] || candidate.ProofDigest == "" {
			return invalid()
		}
		good[id] = true
		if candidate.CreatedAt.After(latest) {
			latest = candidate.CreatedAt
		}
	}
	cutoff := latest.Add(-window)
	selection := RetirementSelection{Targets: []RetirementCandidate{}, Survivors: []RetirementCandidate{}, InertOffsiteGenerationIDs: []string{}, RecoveryEpoch: epoch}
	for _, candidate := range sorted {
		if !good[candidate.PointID] && !candidate.ActivePromise && candidate.CreatedAt.Before(cutoff) {
			selection.Targets = append(selection.Targets, candidate)
		} else {
			selection.Survivors = append(selection.Survivors, candidate)
		}
	}
	// This hashes the complete pre-effect point catalog. Reclaim/repack bytes
	// remain zero until the exact object-dependency graph has been measured; a
	// caller must not turn this provisional selection into a retention lease.
	canonical, err := json.Marshal(sorted)
	if err != nil {
		return invalid()
	}
	hash := sha256.Sum256(append([]byte("local-retirement-catalog-v1\x00"), canonical...))
	selection.ExpectedInventoryDigest = "sha256:" + hex.EncodeToString(hash[:])
	selection.MaxWork = int64(len(selection.Targets))
	return selection, nil
}

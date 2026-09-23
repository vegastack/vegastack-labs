package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
)

const (
	OffsiteStatusPending         = "pending"
	OffsiteStatusFixtureOnly     = "fixture-only"
	OffsiteStatusVerified        = "offsite-verified"
	OffsiteStatusFullPayloadDue  = "full-payload-due"
	OffsiteStatusSiteLossBlocked = "site-loss-blocked"
	OffsiteStatusUncertain       = "uncertain"
	OffsiteStatusFailed          = "failed"
	OffsiteProofFixture          = "fixture"
	OffsiteProofQualified        = "qualified-provider"
)

type WriterSealProof struct {
	GenerationID, ProofClass                                              string
	IssuanceStoppedAt, LastSessionExpiresAt, ObservedAt                   time.Time
	ChildExited, IssuanceStopped, NewPUTDenied, MultipartCompletionDenied bool
}

type OffsiteProof struct {
	ProofID, ProofDigest, Status, ProofClass                                          string
	SourcePointID, SourceSnapshotID, SourceManifestDigest, SourceInventoryDigest      string
	SourceContentDigest, SourceDependencyDigest, SourceResticDigest, KeyReferenceID   string
	GenerationID, RepositoryID, OffsiteSnapshotID, OffsiteInventoryDigest, RuleDigest string
	SourceRevision, StateRevision, RecoveryEpoch, ObjectCount, ObjectBytes            int64
	FullReadAt, ObservedAt                                                            time.Time
	Seal                                                                              WriterSealProof
}

type OffsiteStatus struct {
	GenerationID, Status, ProofClass, LastGoodProofID string
	SourcePointID, RepositoryID, SnapshotID           string
	RecoveryEpoch                                     int64
}

// OffsiteCatalog is the append-only persistence contract. The SQL-backed
// implementation is added only after the integration branch owns the next
// migration number; no caller receives a direct status setter.
type OffsiteCatalog interface {
	AppendPending(context.Context, PendingOffsiteGeneration) error
	GetGeneration(context.Context, string) (PendingOffsiteGeneration, error)
	AppendProof(context.Context, OffsiteProof) error
	ProofExists(context.Context, string, string) (bool, error)
	AdvanceLastGood(context.Context, OffsiteProof, int64) error
	Status(context.Context, string) (OffsiteStatus, error)
}

func ValidateOffsiteProof(pending PendingOffsiteGeneration, proof OffsiteProof) error {
	if !validPendingOffsiteGeneration(pending) || proof.ProofID == "" || proof.ProofDigest != DigestOffsiteProof(proof) ||
		(proof.Status != OffsiteStatusVerified && proof.Status != OffsiteStatusFixtureOnly && proof.Status != OffsiteStatusFullPayloadDue && proof.Status != OffsiteStatusSiteLossBlocked && proof.Status != OffsiteStatusUncertain && proof.Status != OffsiteStatusFailed) ||
		(proof.ProofClass != OffsiteProofFixture && proof.ProofClass != OffsiteProofQualified) ||
		proof.SourcePointID != pending.SourcePointID || proof.SourceSnapshotID != pending.SourceSnapshotID ||
		proof.SourceManifestDigest != pending.SourceManifestDigest || proof.SourceInventoryDigest != pending.SourceInventoryDigest ||
		proof.SourceContentDigest != pending.SourceContentDigest || proof.SourceDependencyDigest != pending.SourceDependencyDigest ||
		proof.SourceResticDigest != pending.SourceResticDigest || proof.KeyReferenceID != pending.KeyReferenceID ||
		proof.GenerationID != pending.GenerationID || proof.RepositoryID != pending.RepositoryID ||
		proof.OffsiteSnapshotID != pending.OffsiteSnapshotID || proof.OffsiteInventoryDigest != pending.OffsiteInventoryDigest ||
		proof.RuleDigest != pending.RuleDigest || proof.SourceRevision != pending.SourceRevision || proof.StateRevision != pending.StateRevision || proof.RecoveryEpoch != pending.RecoveryEpoch ||
		proof.ObjectCount != pending.ObjectCount || proof.ObjectBytes != pending.ObjectBytes || proof.ObservedAt.IsZero() {
		return errors.New("offsite proof does not bind pending generation")
	}
	if proof.Status == OffsiteStatusVerified && (proof.ProofClass != OffsiteProofQualified || !validWriterSeal(pending, proof.Seal, proof.ObservedAt) || proof.FullReadAt.IsZero()) {
		return errors.New("offsite proof is not site-loss qualified")
	}
	return nil
}

func DigestOffsiteProof(proof OffsiteProof) string {
	proof.ProofDigest = ""
	body, err := json.Marshal(proof)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(append([]byte("offsite-proof-v1\x00"), body...))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func CanAdvanceOffsiteLastGood(pending PendingOffsiteGeneration, proof OffsiteProof, currentRevision, currentEpoch int64) error {
	if ValidateOffsiteProof(pending, proof) != nil || proof.Status != OffsiteStatusVerified || proof.ProofClass != OffsiteProofQualified ||
		pending.StateRevision != currentRevision || pending.RecoveryEpoch != currentEpoch || proof.FullReadAt.After(proof.ObservedAt) {
		return errors.New("offsite last-good advancement blocked")
	}
	return nil
}

func validPendingOffsiteGeneration(value PendingOffsiteGeneration) bool {
	if value.SourcePointID == "" || !validObjectName(value.SourceSnapshotID) || !validBackupManifestDigest(value.SourceManifestDigest) ||
		!validBackupManifestDigest(value.SourceInventoryDigest) || !validBackupManifestDigest(value.SourceContentDigest) ||
		!validBackupManifestDigest(value.SourceDependencyDigest) || !validBackupManifestDigest(value.SourceResticDigest) || value.KeyReferenceID == "" ||
		!validOffsiteToken(value.GenerationID) || !validObjectName(value.RepositoryID) || !validObjectName(value.OffsiteSnapshotID) ||
		!validBackupManifestDigest(value.OffsiteInventoryDigest) || !validBackupManifestDigest(value.RuleDigest) ||
		value.SourceRevision < 0 || value.StateRevision < 0 || value.RecoveryEpoch < 0 || value.ObjectCount <= 0 || value.ObjectBytes <= 0 ||
		value.IssuanceStoppedAt.IsZero() || len(value.SessionExpiries) == 0 || len(value.ProtectedRules) != len(protectedGenerationParts) ||
		int64(len(value.Objects)) != value.ObjectCount || DigestOffsiteInventory(value.Objects) != value.OffsiteInventoryDigest {
		return false
	}
	if !validProtectedRules(value.GenerationID, value.ProtectedRules) {
		return false
	}
	var objectBytes int64
	seenObjects := map[string]bool{}
	for _, object := range value.Objects {
		if !validOffsiteObject(object) || seenObjects[object.Key] || object.Bytes > value.ObjectBytes-objectBytes {
			return false
		}
		seenObjects[object.Key] = true
		objectBytes += object.Bytes
	}
	if objectBytes != value.ObjectBytes {
		return false
	}
	for _, expiry := range value.SessionExpiries {
		if expiry.IsZero() {
			return false
		}
	}
	return true
}

func validProtectedRules(generationID string, rules []adapter.RetentionRule) bool {
	if len(rules) != len(protectedGenerationParts) {
		return false
	}
	seenIDs, prefixes := map[string]bool{}, make([]string, 0, len(rules))
	for _, rule := range rules {
		if !validOffsiteToken(rule.RuleID) || seenIDs[rule.RuleID] || !validOffsitePrefix(strings.TrimSuffix(rule.Prefix, "/")) {
			return false
		}
		seenIDs[rule.RuleID] = true
		prefixes = append(prefixes, rule.Prefix)
	}
	var base string
	for _, prefix := range prefixes {
		if strings.HasSuffix(prefix, "/config") {
			base = strings.TrimSuffix(prefix, "/config")
			break
		}
	}
	if base == "" || !strings.HasSuffix(base, "/"+generationID) {
		return false
	}
	want := make([]string, 0, len(protectedGenerationParts))
	for _, part := range protectedGenerationParts {
		want = append(want, path.Join(base, part)+map[bool]string{true: "/", false: ""}[part != "config"])
	}
	slices.Sort(prefixes)
	slices.Sort(want)
	return slices.Equal(prefixes, want)
}

// ValidatePendingOffsiteGeneration exposes the same strict receipt boundary to
// persistence implementations without allowing them to reinterpret it.
func ValidatePendingOffsiteGeneration(value PendingOffsiteGeneration) error {
	if !validPendingOffsiteGeneration(value) {
		return errors.New("invalid pending offsite generation")
	}
	return nil
}

func validWriterSeal(pending PendingOffsiteGeneration, seal WriterSealProof, observedAt time.Time) bool {
	last := pending.SessionExpiries[0]
	for _, expiry := range pending.SessionExpiries[1:] {
		if expiry.After(last) {
			last = expiry
		}
	}
	return seal.GenerationID == pending.GenerationID && seal.ProofClass == OffsiteProofQualified && seal.ChildExited && seal.IssuanceStopped &&
		seal.NewPUTDenied && seal.MultipartCompletionDenied && seal.IssuanceStoppedAt.Equal(pending.IssuanceStoppedAt) &&
		seal.LastSessionExpiresAt.Equal(last) && !seal.ObservedAt.Before(last) && !seal.ObservedAt.Before(pending.IssuanceStoppedAt) &&
		!observedAt.Before(seal.ObservedAt)
}

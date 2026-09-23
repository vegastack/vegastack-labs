package backup

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
)

type OffsiteGenerationObservation struct {
	GenerationID, RepositoryID, InventoryDigest, RuleDigest                         string
	SourcePointID, SourceSnapshotID, SourceManifestDigest, SourceInventoryDigest    string
	SourceContentDigest, SourceDependencyDigest, SourceResticDigest, KeyReferenceID string
	SnapshotIDs                                                                     []string
	ProtectedRules                                                                  []adapter.RetentionRule
	Objects                                                                         []OffsiteObject
	ObjectCount, ObjectBytes                                                        int64
	MetadataValid, FullReadSucceeded                                                bool
	FullReadAt, ObservedAt                                                          time.Time
}

type OffsiteExpectedPointSource interface {
	ObserveExpectedPoint(context.Context, PendingOffsiteGeneration) (OffsiteGenerationObservation, error)
}

type OffsiteVerifierConfig struct {
	Source             OffsiteExpectedPointSource
	ProofID            string
	ProofClass         string
	Clock              func() time.Time
	FullReadMaximumAge time.Duration
}

type OffsiteCutoffProbe interface {
	DenyNewPUT(context.Context, string) (bool, error)
	DenyMultipartCompletion(context.Context, string) (bool, error)
}

type OffsiteCutoffWaiter interface {
	AwaitWriterCutoff(context.Context, PendingOffsiteGeneration) (time.Time, error)
}

func VerifyOffsitePoint(ctx context.Context, config OffsiteVerifierConfig, pending PendingOffsiteGeneration, seal WriterSealProof) (OffsiteProof, error) {
	if config.Source == nil || config.ProofID == "" || (config.ProofClass != OffsiteProofFixture && config.ProofClass != OffsiteProofQualified) || !validPendingOffsiteGeneration(pending) ||
		config.FullReadMaximumAge <= 0 || config.FullReadMaximumAge > 31*24*time.Hour {
		return OffsiteProof{}, errors.New("offsite verification blocked")
	}
	now := time.Now().UTC()
	if config.Clock != nil {
		now = config.Clock().UTC()
	}
	observed, err := config.Source.ObserveExpectedPoint(ctx, pending)
	if err != nil {
		return OffsiteProof{}, err
	}
	snapshotIDs := append([]string(nil), observed.SnapshotIDs...)
	slices.Sort(snapshotIDs)
	observedRules := append([]adapter.RetentionRule(nil), observed.ProtectedRules...)
	pendingRules := append([]adapter.RetentionRule(nil), pending.ProtectedRules...)
	slices.SortFunc(observedRules, compareRetentionRule)
	slices.SortFunc(pendingRules, compareRetentionRule)
	observedObjects := append([]OffsiteObject(nil), observed.Objects...)
	pendingObjects := append([]OffsiteObject(nil), pending.Objects...)
	slices.SortFunc(observedObjects, compareOffsiteObject)
	slices.SortFunc(pendingObjects, compareOffsiteObject)
	if observed.GenerationID != pending.GenerationID || observed.RepositoryID != pending.RepositoryID ||
		observed.SourcePointID != pending.SourcePointID || observed.SourceSnapshotID != pending.SourceSnapshotID ||
		observed.SourceManifestDigest != pending.SourceManifestDigest || observed.SourceInventoryDigest != pending.SourceInventoryDigest ||
		observed.SourceContentDigest != pending.SourceContentDigest || observed.SourceDependencyDigest != pending.SourceDependencyDigest ||
		observed.SourceResticDigest != pending.SourceResticDigest || observed.KeyReferenceID != pending.KeyReferenceID ||
		len(snapshotIDs) != 1 || snapshotIDs[0] != pending.OffsiteSnapshotID || observed.InventoryDigest != pending.OffsiteInventoryDigest ||
		observed.RuleDigest != pending.RuleDigest || observed.ObjectCount != pending.ObjectCount || observed.ObjectBytes != pending.ObjectBytes ||
		!slices.Equal(observedRules, pendingRules) || !slices.Equal(observedObjects, pendingObjects) ||
		DigestOffsiteInventory(observedObjects) != observed.InventoryDigest ||
		!observed.MetadataValid || !observed.FullReadSucceeded || observed.FullReadAt.IsZero() ||
		observed.ObservedAt.IsZero() || observed.ObservedAt.After(now) || observed.FullReadAt.After(observed.ObservedAt) ||
		observed.FullReadAt.Before(pending.IssuanceStoppedAt) || observed.ObservedAt.Before(pending.IssuanceStoppedAt) ||
		observed.ObservedAt.Sub(observed.FullReadAt) > config.FullReadMaximumAge {
		return OffsiteProof{}, errors.New("offsite expected point verification failed")
	}
	status := OffsiteStatusFixtureOnly
	if config.ProofClass == OffsiteProofQualified {
		if !validWriterSeal(pending, seal, observed.ObservedAt) {
			return OffsiteProof{}, errors.New("offsite writer remains live")
		}
		status = OffsiteStatusVerified
	}
	proof := OffsiteProof{ProofID: config.ProofID, Status: status, ProofClass: config.ProofClass,
		SourcePointID: pending.SourcePointID, SourceSnapshotID: pending.SourceSnapshotID, SourceManifestDigest: pending.SourceManifestDigest,
		SourceInventoryDigest: pending.SourceInventoryDigest, SourceContentDigest: pending.SourceContentDigest, SourceDependencyDigest: pending.SourceDependencyDigest,
		SourceResticDigest: pending.SourceResticDigest, KeyReferenceID: pending.KeyReferenceID, GenerationID: pending.GenerationID, RepositoryID: pending.RepositoryID,
		OffsiteSnapshotID: pending.OffsiteSnapshotID, OffsiteInventoryDigest: pending.OffsiteInventoryDigest, RuleDigest: pending.RuleDigest,
		SourceRevision: pending.SourceRevision, StateRevision: pending.StateRevision, RecoveryEpoch: pending.RecoveryEpoch, ObjectCount: pending.ObjectCount, ObjectBytes: pending.ObjectBytes,
		FullReadAt: observed.FullReadAt, ObservedAt: observed.ObservedAt, Seal: seal}
	proof.ProofDigest = DigestOffsiteProof(proof)
	if err := ValidateOffsiteProof(pending, proof); err != nil {
		return OffsiteProof{}, err
	}
	return proof, nil
}

func compareRetentionRule(left, right adapter.RetentionRule) int {
	if left.Prefix == right.Prefix {
		return strings.Compare(left.RuleID, right.RuleID)
	}
	return strings.Compare(left.Prefix, right.Prefix)
}

func compareOffsiteObject(left, right OffsiteObject) int {
	return strings.Compare(left.Key, right.Key)
}

func SealWriter(ctx context.Context, pending PendingOffsiteGeneration, proofClass string, now time.Time, probe OffsiteCutoffProbe) (WriterSealProof, error) {
	if !validPendingOffsiteGeneration(pending) || probe == nil || proofClass != OffsiteProofQualified || now.IsZero() {
		return WriterSealProof{}, errors.New("offsite writer seal blocked")
	}
	last := pending.SessionExpiries[0]
	for _, expiry := range pending.SessionExpiries[1:] {
		if expiry.After(last) {
			last = expiry
		}
	}
	if waiter, ok := probe.(OffsiteCutoffWaiter); ok {
		observedAt, err := waiter.AwaitWriterCutoff(ctx, pending)
		if err != nil {
			return WriterSealProof{}, errors.New("offsite writer cutoff wait failed")
		}
		now = observedAt.UTC()
	}
	if now.Before(last) || now.Before(pending.IssuanceStoppedAt) {
		return WriterSealProof{}, errors.New("offsite writer session remains live")
	}
	putDenied, putErr := probe.DenyNewPUT(ctx, pending.GenerationID)
	multipartDenied, multipartErr := probe.DenyMultipartCompletion(ctx, pending.GenerationID)
	if putErr != nil || multipartErr != nil || !putDenied || !multipartDenied {
		return WriterSealProof{}, errors.New("offsite writer cutoff unproven")
	}
	return WriterSealProof{GenerationID: pending.GenerationID, ProofClass: proofClass, IssuanceStoppedAt: pending.IssuanceStoppedAt,
		LastSessionExpiresAt: last, ObservedAt: now.UTC(), ChildExited: true, IssuanceStopped: true, NewPUTDenied: true, MultipartCompletionDenied: true}, nil
}

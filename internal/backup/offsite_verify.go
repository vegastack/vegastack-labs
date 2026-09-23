package backup

import (
	"context"
	"errors"
	"slices"
	"time"
)

type OffsiteGenerationObservation struct {
	GenerationID, RepositoryID, InventoryDigest, RuleDigest                         string
	SourcePointID, SourceSnapshotID, SourceManifestDigest, SourceInventoryDigest    string
	SourceContentDigest, SourceDependencyDigest, SourceResticDigest, KeyReferenceID string
	SnapshotIDs                                                                     []string
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
	if observed.GenerationID != pending.GenerationID || observed.RepositoryID != pending.RepositoryID ||
		observed.SourcePointID != pending.SourcePointID || observed.SourceSnapshotID != pending.SourceSnapshotID ||
		observed.SourceManifestDigest != pending.SourceManifestDigest || observed.SourceInventoryDigest != pending.SourceInventoryDigest ||
		observed.SourceContentDigest != pending.SourceContentDigest || observed.SourceDependencyDigest != pending.SourceDependencyDigest ||
		observed.SourceResticDigest != pending.SourceResticDigest || observed.KeyReferenceID != pending.KeyReferenceID ||
		len(snapshotIDs) != 1 || snapshotIDs[0] != pending.OffsiteSnapshotID || observed.InventoryDigest != pending.OffsiteInventoryDigest ||
		observed.RuleDigest != pending.RuleDigest || observed.ObjectCount != pending.ObjectCount || observed.ObjectBytes != pending.ObjectBytes ||
		!observed.MetadataValid || !observed.FullReadSucceeded || observed.FullReadAt.IsZero() ||
		observed.ObservedAt.IsZero() || observed.ObservedAt.After(now) || observed.FullReadAt.After(observed.ObservedAt) ||
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
		SourceRevision: pending.SourceRevision, RecoveryEpoch: pending.RecoveryEpoch, ObjectCount: pending.ObjectCount, ObjectBytes: pending.ObjectBytes,
		FullReadAt: observed.FullReadAt, ObservedAt: observed.ObservedAt, Seal: seal}
	proof.ProofDigest = DigestOffsiteProof(proof)
	if err := ValidateOffsiteProof(pending, proof); err != nil {
		return OffsiteProof{}, err
	}
	return proof, nil
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
	if now.Before(last) {
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

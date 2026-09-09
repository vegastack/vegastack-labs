package inventory

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"unicode/utf8"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

type Service struct {
	repository   DraftRepository
	newID        IDGenerator
	destinations []audit.OutboxRequirement
}

func NewService(repository DraftRepository, generator IDGenerator, destinations []audit.OutboxRequirement) (*Service, error) {
	if repository == nil || audit.ValidateOutboxRequirements(destinations) != nil {
		return nil, newError(generated.ErrorCodeInputInvalid, targetDraft)
	}
	if generator == nil {
		generator = NewDraftID
	}
	return &Service{repository: repository, newID: generator, destinations: slices.Clone(destinations)}, nil
}

func NewDraftID() (DraftID, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", newError(generated.ErrorCodeDependencyUnavailable, "random-source")
	}
	return DraftID("draft_" + hex.EncodeToString(random)), nil
}

func (service *Service) ValidateAndStore(ctx context.Context, request ImportRequest) (ImportResult, error) {
	if service == nil || service.repository == nil || len(request.IdempotencyKey) == 0 || len(request.IdempotencyKey) > MaxIdempotencyBytes || !utf8.ValidString(request.IdempotencyKey) || request.CorrelationID == "" {
		return ImportResult{}, newError(generated.ErrorCodeInputInvalid, targetDraft)
	}
	if ctx.Err() != nil {
		return ImportResult{}, newError(generated.ErrorCodeInterrupted, targetContext)
	}
	principal, ok := identity.PrincipalFromContext(ctx)
	if !ok {
		return ImportResult{}, newError(generated.ErrorCodeAuthenticationRequired, targetDraft)
	}
	attribution, err := audit.NewAttribution(principal, nil, nil)
	if err != nil {
		return ImportResult{}, newError(generated.ErrorCodeInputInvalid, targetDraft)
	}
	normalized, err := NormalizeAndValidate(ctx, request.Decoded)
	if err != nil {
		return ImportResult{}, err
	}
	draftID, err := service.newID()
	if err != nil || draftID == "" || len(draftID) > MaxTokenBytes || !utf8.ValidString(string(draftID)) {
		return ImportResult{}, newError(generated.ErrorCodeDependencyUnavailable, "draft-id")
	}
	keyDigest := sha256.Sum256([]byte(request.IdempotencyKey))
	after := audit.Fingerprint(normalized.ContentDigest)
	put, err := service.repository.Put(ctx, PutDraftRequest{
		ExpectedStateRevision: request.ExpectedStateRevision,
		IdempotencyKeyDigest:  "sha256:" + hex.EncodeToString(keyDigest[:]),
		CandidateDigest:       normalized.ContentDigest,
		DraftID:               draftID,
		Draft:                 normalized,
		Event:                 audit.EventDraft{Type: "inventory.draft.persisted", CorrelationID: request.CorrelationID, Attribution: attribution, Target: audit.Target{Kind: "inventory-draft", ID: string(draftID)}, After: &after},
		Destinations:          slices.Clone(service.destinations),
	})
	if err != nil {
		return ImportResult{}, sanitizeRepositoryError(err)
	}
	return ImportResult{DraftID: put.Ref.ID, DraftRevision: put.Ref.Revision, ValidationStatus: normalized.ValidationStatus, SourceDigest: normalized.Candidate.Source.Digest, ContentDigest: normalized.ContentDigest, StateRevision: put.CommitStateRevision, RecoveryEpoch: put.RecoveryEpoch, EventID: put.EventID, Created: put.Created, Counts: normalized.Counts, Findings: slices.Clone(normalized.Findings)}, nil
}

type codedError interface{ Code() string }

func sanitizeRepositoryError(err error) error {
	if coded, ok := err.(codedError); ok {
		switch coded.Code() {
		case generated.ErrorCodeStateConflict, generated.ErrorCodeInterrupted, generated.ErrorCodeInputInvalid, generated.ErrorCodeRecoveryEpochMismatch, generated.ErrorCodePrerequisiteBlocked, generated.ErrorCodeDependencyUnavailable, generated.ErrorCodeIntegrityFailure:
			return newError(coded.Code(), targetDraft)
		}
	}
	return newError(generated.ErrorCodeDependencyUnavailable, targetDraft)
}

var _ ImportService = (*Service)(nil)

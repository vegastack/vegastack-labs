package stateexport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"unicode/utf8"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/result"
)

type Config struct {
	Source       SnapshotSource
	Audit        AuditRepository
	Artifacts    ArtifactStore
	Signer       Signer
	Verifier     Verifier
	Build        result.BuildInfo
	Destinations []audit.OutboxRequirement
}

type Service struct {
	config Config
}

func NewService(config Config) (*Service, error) {
	if config.Source == nil || config.Audit == nil || config.Artifacts == nil || audit.ValidateOutboxRequirements(config.Destinations) != nil {
		return nil, exportError(generated.ErrorCodeInputInvalid, "inventory-export-service")
	}
	config.Destinations = slices.Clone(config.Destinations)
	if config.Build.SourceRevision != nil {
		copy := *config.Build.SourceRevision
		config.Build.SourceRevision = &copy
	}
	return &Service{config: config}, nil
}

func (service *Service) Export(ctx context.Context, request Request) (Result, error) {
	if service == nil || service.config.Source == nil || len(request.IdempotencyKey) == 0 || len(request.IdempotencyKey) > 256 || !utf8.ValidString(request.IdempotencyKey) ||
		request.CorrelationID == "" || request.Draft.ID == "" || request.Draft.Revision < 1 {
		return Result{}, exportError(generated.ErrorCodeInputInvalid, "inventory-export-request")
	}
	if ctx.Err() != nil {
		return Result{}, exportError(generated.ErrorCodeInterrupted, "inventory-export-request")
	}
	principal, ok := identity.PrincipalFromContext(ctx)
	if !ok {
		return Result{}, exportError(generated.ErrorCodeAuthenticationRequired, "inventory-export-request")
	}
	attribution, err := audit.NewAttribution(principal, nil, nil)
	if err != nil {
		return Result{}, exportError(generated.ErrorCodeInputInvalid, "inventory-export-request")
	}
	target, err := ExportTarget(request.Draft)
	if err != nil {
		return Result{}, err
	}
	snapshot, err := service.config.Source.SnapshotInventoryDraft(ctx, request.Draft)
	if err != nil {
		return Result{}, sanitizeExportDependency(err, "inventory-export-draft")
	}
	if snapshot.Draft.Ref != request.Draft || snapshot.StateRevision < 0 || snapshot.RecoveryEpoch < 0 {
		return Result{}, exportError(generated.ErrorCodeIntegrityFailure, "inventory-export-draft")
	}
	payload := Payload{
		Schema: PayloadSchema, SchemaVersion: SchemaVersion, ExportKind: ExportKind, SubjectKind: SubjectKind,
		RecoveryEpoch: snapshot.RecoveryEpoch, StateRevision: snapshot.StateRevision,
		ToolVersion: service.config.Build.ToolVersion, ReleaseBuildID: service.config.Build.ReleaseBuildID,
		SourceRevision: cloneString(service.config.Build.SourceRevision), Contents: []KindCount{{Kind: "inventory-draft", Count: 1}}, Draft: snapshot.Draft,
	}
	_, payloadDigest, err := CanonicalPayload(payload)
	if err != nil {
		return Result{}, err
	}
	exportID := audit.Fingerprint(digestString(payloadDigest))
	var current *CurrentPointer
	trustAvailable := service.config.Signer != nil && service.config.Verifier != nil
	if trustAvailable {
		current, err = service.config.Artifacts.InspectCurrent(ctx)
		if err != nil {
			return Result{}, sanitizeExportDependency(err, "inventory-export-artifacts")
		}
		if current != nil {
			if err := service.verifyArtifact(ctx, *current); err != nil {
				return Result{}, err
			}
		}
	}
	var before *audit.Fingerprint
	if current != nil {
		value := audit.Fingerprint(current.ArtifactID)
		before = &value
	}
	requestKey, requestDigest := exportIntentDigests(request, "requested")
	requested, err := service.config.Audit.AppendExportAudit(ctx, AuditAppendRequest{
		ExpectedStateRevision: snapshot.StateRevision, ExpectedRecoveryEpoch: snapshot.RecoveryEpoch,
		Idempotency:  audit.IntentKey{Scope: "inventory-export-requested", KeyDigest: requestKey, RequestDigest: requestDigest},
		Event:        audit.EventDraft{Type: "inventory.export.requested", CorrelationID: request.CorrelationID, Attribution: attribution, Target: target, Before: before, After: &exportID},
		Destinations: slices.Clone(service.config.Destinations),
	})
	if err != nil {
		return Result{}, sanitizeExportDependency(err, "inventory-export-audit")
	}
	terminal := func(eventType audit.EventType) error {
		key, digest := exportIntentDigests(request, string(eventType))
		_, terminalErr := service.config.Audit.AppendExportAudit(ctx, AuditAppendRequest{
			ExpectedStateRevision: requested.StateRevision, ExpectedRecoveryEpoch: requested.RecoveryEpoch,
			Idempotency:  audit.IntentKey{Scope: "inventory-export-terminal", KeyDigest: key, RequestDigest: digest},
			Event:        audit.EventDraft{Type: eventType, CorrelationID: request.CorrelationID, CausationID: &requested.EventID, Attribution: attribution, Target: target, Before: before, After: &exportID},
			Destinations: slices.Clone(service.config.Destinations),
		})
		return terminalErr
	}
	fail := func(code, target string) (Result, error) {
		if err := terminal("inventory.export.failed"); err != nil {
			return Result{}, exportError(generated.ErrorCodeDependencyUnavailable, "inventory-export-audit")
		}
		return Result{}, exportError(code, target)
	}
	if !trustAvailable {
		return fail(generated.ErrorCodePrerequisiteBlocked, "inventory-export-trust")
	}
	signature, err := service.config.Signer.Sign(ctx, SignRequest{Purpose: SigningPurpose, Digest: payloadDigest})
	if err != nil {
		if ctx.Err() != nil {
			return fail(generated.ErrorCodeInterrupted, "inventory-export-signature")
		}
		return fail(generated.ErrorCodeDependencyUnavailable, "inventory-export-signature")
	}
	document := SignedExport{Schema: SignedExportSchema, SchemaVersion: SchemaVersion, Payload: payload, ContentDigest: string(exportID), Signature: signature, VerificationStatus: VerificationVerified}
	if err := VerifySignedExport(ctx, service.config.Verifier, document); err != nil {
		return fail(generated.ErrorCodeIntegrityFailure, "inventory-export-signature")
	}
	canonical, artifactDigest, err := CanonicalSignedExport(document)
	if err != nil {
		return fail(generated.ErrorCodeIntegrityFailure, "inventory-export-document")
	}
	publication, err := service.config.Artifacts.Publish(ctx, PublishRequest{ArtifactID: digestString(artifactDigest), ContentDigest: string(exportID), Bytes: canonical})
	if err != nil {
		return fail(codeForExportDependency(err), "inventory-export-artifacts")
	}
	if err := terminal("inventory.export.published"); err != nil {
		return Result{}, exportError(generated.ErrorCodeDependencyUnavailable, "inventory-export-audit")
	}
	return Result{
		ExportID: string(exportID), SubjectKind: SubjectKind, Draft: request.Draft, StateRevision: snapshot.StateRevision, RecoveryEpoch: snapshot.RecoveryEpoch,
		ContentDigest: string(exportID), Algorithm: signature.Algorithm, KeyID: signature.KeyID, KeyFingerprint: signature.KeyFingerprint,
		VerificationStatus: VerificationVerified, PublicationStatus: "published", SignedExport: document, CanonicalBytes: slices.Clone(canonical), Created: publication.Created,
	}, nil
}

func (service *Service) Reconcile(ctx context.Context, limit int) (ReconcileResult, error) {
	if service == nil || service.config.Audit == nil || service.config.Artifacts == nil || limit < 1 || limit > 64 {
		return ReconcileResult{}, exportError(generated.ErrorCodeInputInvalid, "inventory-export-reconcile")
	}
	if service.config.Verifier == nil {
		return ReconcileResult{}, exportError(generated.ErrorCodePrerequisiteBlocked, "inventory-export-trust")
	}
	pending, err := service.config.Audit.PendingExportRequests(ctx, limit)
	if err != nil {
		return ReconcileResult{}, sanitizeExportDependency(err, "inventory-export-audit")
	}
	resultValue := ReconcileResult{Examined: len(pending)}
	for _, item := range pending {
		if err := service.reconcileOne(ctx, item); err != nil {
			return resultValue, err
		}
		resultValue.Interrupted++
	}
	return resultValue, nil
}

func (service *Service) reconcileOne(ctx context.Context, pending PendingExportRequest) error {
	target, err := ExportTarget(pending.Draft)
	if err != nil || !audit.ValidFingerprint(pending.RequestedDigest) || string(pending.RequestedDigest) != pending.ExportID {
		return exportError(generated.ErrorCodeIntegrityFailure, "inventory-export-audit")
	}
	current, err := service.config.Artifacts.InspectCurrent(ctx)
	if err != nil {
		return sanitizeExportDependency(err, "inventory-export-artifacts")
	}
	if current != nil {
		if err := service.verifyArtifact(ctx, *current); err != nil {
			return err
		}
	}
	if current != nil && current.ContentDigest == string(pending.RequestedDigest) {
		var previous *CurrentPointer
		if pending.PreviousDigest != nil {
			raw, err := service.config.Artifacts.ReadArtifact(ctx, string(*pending.PreviousDigest))
			if err != nil {
				return sanitizeExportDependency(err, "inventory-export-artifacts")
			}
			document, err := DecodeSignedExport(raw)
			if err != nil || VerifySignedExport(ctx, service.config.Verifier, document) != nil {
				return exportError(generated.ErrorCodeIntegrityFailure, "inventory-export-artifacts")
			}
			value := CurrentPointer{Schema: PointerSchema, SchemaVersion: SchemaVersion, ExportKind: ExportKind, ArtifactID: string(*pending.PreviousDigest), ContentDigest: document.ContentDigest}
			previous = &value
		}
		if err := service.config.Artifacts.RestoreCurrent(ctx, *current, previous); err != nil {
			return sanitizeExportDependency(err, "inventory-export-artifacts")
		}
	}
	key := fingerprintOf(fmt.Sprintf("interrupted:%d", pending.EventID))
	digest := fingerprintOf(fmt.Sprintf("%s\n%s\n%d", pending.CorrelationID, pending.ExportID, pending.EventID))
	_, err = service.config.Audit.AppendExportAudit(ctx, AuditAppendRequest{
		ExpectedStateRevision: pending.StateRevision, ExpectedRecoveryEpoch: pending.RecoveryEpoch,
		Idempotency: audit.IntentKey{Scope: "inventory-export-terminal", KeyDigest: key, RequestDigest: digest},
		Event: audit.EventDraft{Type: "inventory.export.interrupted", CorrelationID: pending.CorrelationID, CausationID: &pending.EventID, Attribution: pending.Attribution,
			Target: target, Before: pending.PreviousDigest, After: &pending.RequestedDigest},
		Destinations: slices.Clone(service.config.Destinations),
	})
	if err != nil {
		return sanitizeExportDependency(err, "inventory-export-audit")
	}
	return nil
}

func (service *Service) verifyArtifact(ctx context.Context, pointer CurrentPointer) error {
	raw, err := service.config.Artifacts.ReadArtifact(ctx, pointer.ArtifactID)
	if err != nil {
		return sanitizeExportDependency(err, "inventory-export-artifacts")
	}
	document, err := DecodeSignedExport(raw)
	if err != nil || document.ContentDigest != pointer.ContentDigest || VerifySignedExport(ctx, service.config.Verifier, document) != nil {
		return exportError(generated.ErrorCodeIntegrityFailure, "inventory-export-artifacts")
	}
	return nil
}

func exportIntentDigests(request Request, stage string) (audit.Fingerprint, audit.Fingerprint) {
	key := sha256.Sum256([]byte(request.IdempotencyKey + "\x00" + stage))
	digest := sha256.Sum256([]byte(fmt.Sprintf("%s\n%s\n%d\n%s", request.CorrelationID, request.Draft.ID, request.Draft.Revision, stage)))
	return audit.Fingerprint("sha256:" + hex.EncodeToString(key[:])), audit.Fingerprint("sha256:" + hex.EncodeToString(digest[:]))
}

func fingerprintOf(value string) audit.Fingerprint {
	digest := sha256.Sum256([]byte(value))
	return audit.Fingerprint("sha256:" + hex.EncodeToString(digest[:]))
}

func codeForExportDependency(err error) string {
	if stable, ok := failure.As(err); ok {
		switch stable.Code {
		case generated.ErrorCodeInputInvalid, generated.ErrorCodeStateConflict, generated.ErrorCodeInterrupted, generated.ErrorCodeRecoveryEpochMismatch, generated.ErrorCodePrerequisiteBlocked, generated.ErrorCodeDependencyUnavailable, generated.ErrorCodeIntegrityFailure:
			return stable.Code
		}
	}
	return generated.ErrorCodeDependencyUnavailable
}

func sanitizeExportDependency(err error, target string) error {
	return exportError(codeForExportDependency(err), target)
}

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

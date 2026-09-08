package backup

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/vegastack/vegastack-labs/internal/store"
)

const (
	restoreVerified = "verified"
	restoreFailed   = "failed"
)

// Service implements the migration-recovery port without opening SQLite. The
// store package remains the sole owner of every database connection.
type Service struct {
	mu      sync.Mutex
	config  Config
	layout  artifactLayout
	entropy interface{ Read([]byte) (int, error) }
}

func New(config Config) (*Service, error) {
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.Entropy == nil {
		config.Entropy = rand.Reader
	}
	layout, err := newArtifactLayout(config)
	if err != nil {
		return nil, err
	}
	return &Service{config: config, layout: layout, entropy: config.Entropy}, nil
}

func (service *Service) Prepare(ctx context.Context, source store.MigrationSource, request store.MigrationRequest) (store.VerifiedSnapshot, error) {
	if service == nil || source == nil {
		return store.VerifiedSnapshot{}, migrationError()
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return store.VerifiedSnapshot{}, interruptedError()
	}
	if !validateMigrationRequest(request) {
		return store.VerifiedSnapshot{}, migrationError()
	}
	createdAt := service.config.Clock().UTC()
	snapshotID, err := randomID(service.entropy)
	if err != nil {
		return store.VerifiedSnapshot{}, migrationError()
	}
	staged, err := service.layout.BeginGeneration(ctx, snapshotID)
	if err != nil {
		return store.VerifiedSnapshot{}, classifyOperation(ctx, err)
	}
	policy := store.BackupStepPolicy{PagesPerStep: DefaultPagesPerStep, BusyBudget: request.BusyBudget}
	if err := source.OnlineBackup(ctx, staged.database, policy); err != nil {
		return store.VerifiedSnapshot{}, classifyOperation(ctx, err)
	}
	identity, size, databaseDigest, err := service.layout.SealDatabase(ctx, staged)
	if err != nil {
		return store.VerifiedSnapshot{}, classifyOperation(ctx, err)
	}
	staged.databaseIdentity = identity
	expectation := store.SnapshotExpectation{SchemaVersion: request.CurrentSchemaVersion, Revision: request.CurrentRevision, CatalogSHA256: request.CatalogSHA256}
	inspection, err := source.InspectSnapshot(ctx, staged.database, expectation)
	if err != nil {
		return store.VerifiedSnapshot{}, classifyOperation(ctx, err)
	}
	if inspection.IntegrityStatus != store.IntegrityVerified || inspection.SchemaVersion != request.CurrentSchemaVersion || inspection.Revision != request.CurrentRevision || !safeSQLiteVersion(inspection.SQLiteVersion) {
		return store.VerifiedSnapshot{}, integrityError()
	}
	verifiedAt := service.config.Clock().UTC()
	manifest := Manifest{
		Schema:                ManifestSchema,
		SchemaVersion:         ManifestVersion,
		SnapshotID:            snapshotID,
		Purpose:               snapshotPurpose,
		ToolVersion:           request.ToolVersion,
		BuildVersion:          request.BuildVersion,
		SQLiteVersion:         inspection.SQLiteVersion,
		DatabaseSchemaVersion: inspection.SchemaVersion,
		CatalogSHA256:         hex.EncodeToString(request.CatalogSHA256[:]),
		StateRevision:         inspection.Revision.StateRevision,
		RecoveryEpoch:         inspection.Revision.RecoveryEpoch,
		DatabaseSHA256:        hex.EncodeToString(databaseDigest[:]),
		DatabaseSize:          size,
		Verification:          VerificationPassed,
		CreatedAt:             createdAt.Format(time.RFC3339Nano),
		VerifiedAt:            verifiedAt.Format(time.RFC3339Nano),
	}
	body, err := marshalManifest(manifest)
	if err != nil {
		return store.VerifiedSnapshot{}, integrityError()
	}
	if err := service.layout.WriteManifest(ctx, staged, body); err != nil {
		return store.VerifiedSnapshot{}, classifyOperation(ctx, err)
	}
	if _, err := service.layout.Publish(ctx, staged); err != nil {
		return store.VerifiedSnapshot{}, classifyOperation(ctx, err)
	}
	return store.VerifiedSnapshot{
		SnapshotID:    snapshotID,
		SchemaVersion: inspection.SchemaVersion,
		Revision:      inspection.Revision,
		CatalogSHA256: request.CatalogSHA256,
	}, nil
}

func validateMigrationRequest(request store.MigrationRequest) bool {
	return request.Purpose == snapshotPurpose &&
		safeVersion(request.ToolVersion) &&
		safeVersion(request.BuildVersion) &&
		request.CurrentSchemaVersion > 0 &&
		request.TargetSchemaVersion > request.CurrentSchemaVersion &&
		request.CatalogSHA256 != ([32]byte{}) &&
		request.CurrentRevision.StateRevision >= 0 &&
		request.CurrentRevision.RecoveryEpoch >= 0 &&
		request.BusyBudget > 0 &&
		!request.RequestedAt.IsZero()
}

func (service *Service) VerifyRestorable(ctx context.Context, source store.MigrationSource, snapshot store.VerifiedSnapshot) (store.RestoreEvidence, error) {
	startedAt := time.Now().UTC()
	if service != nil && service.config.Clock != nil {
		startedAt = service.config.Clock().UTC()
	}
	evidence := store.RestoreEvidence{
		SnapshotID:    snapshot.SnapshotID,
		Status:        restoreFailed,
		SchemaVersion: snapshot.SchemaVersion,
		Revision:      snapshot.Revision,
		StartedAt:     startedAt,
	}
	if service == nil || source == nil {
		return finishRestoreEvidence(service, evidence, migrationError())
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return finishRestoreEvidence(service, evidence, interruptedError())
	}
	if !validSnapshotID(snapshot.SnapshotID) || snapshot.SchemaVersion == 0 || snapshot.Revision.StateRevision < 0 || snapshot.Revision.RecoveryEpoch < 0 || snapshot.CatalogSHA256 == ([32]byte{}) {
		return finishRestoreEvidence(service, evidence, integrityError())
	}
	published, body, err := service.layout.OpenPublished(ctx, snapshot.SnapshotID)
	if err != nil {
		return finishRestoreEvidence(service, evidence, classifyOperation(ctx, err))
	}
	manifest, err := parseManifest(body)
	if err != nil || manifest.SnapshotID != snapshot.SnapshotID || manifest.DatabaseSchemaVersion != snapshot.SchemaVersion || manifest.StateRevision != snapshot.Revision.StateRevision || manifest.RecoveryEpoch != snapshot.Revision.RecoveryEpoch || manifest.CatalogSHA256 != hex.EncodeToString(snapshot.CatalogSHA256[:]) {
		return finishRestoreEvidence(service, evidence, integrityError())
	}
	target, err := service.layout.BeginRestore(ctx, snapshot.SnapshotID)
	if err != nil {
		return finishRestoreEvidence(service, evidence, classifyOperation(ctx, err))
	}
	failAndClean := func(primary error) (store.RestoreEvidence, error) {
		classifiedPrimary := classifyOperation(ctx, primary)
		if cleanupErr := service.layout.RemoveRestore(context.WithoutCancel(ctx), target); cleanupErr != nil && primary == nil {
			classifiedPrimary = integrityError()
		}
		return finishRestoreEvidence(service, evidence, classifiedPrimary)
	}
	if err := source.RestoreSnapshot(ctx, published.database, target.database); err != nil {
		return failAndClean(err)
	}
	_, restoredSize, err := service.layout.SealRestore(ctx, target)
	if err != nil || restoredSize <= 0 {
		return failAndClean(classified(err, integrityError()))
	}
	expectation := store.SnapshotExpectation{SchemaVersion: snapshot.SchemaVersion, Revision: snapshot.Revision, CatalogSHA256: snapshot.CatalogSHA256}
	inspection, err := source.InspectSnapshot(ctx, target.database, expectation)
	if err != nil {
		return failAndClean(err)
	}
	if inspection.IntegrityStatus != store.IntegrityVerified || inspection.SchemaVersion != snapshot.SchemaVersion || inspection.Revision != snapshot.Revision || inspection.SQLiteVersion != manifest.SQLiteVersion {
		return failAndClean(integrityError())
	}
	if err := service.layout.RemoveRestore(context.WithoutCancel(ctx), target); err != nil {
		return finishRestoreEvidence(service, evidence, integrityError())
	}
	evidence.Status = restoreVerified
	evidence.FailureCode = ""
	completedAt := service.config.Clock().UTC()
	evidence.CompletedAt = completedAt
	return evidence, nil
}

func finishRestoreEvidence(service *Service, evidence store.RestoreEvidence, err error) (store.RestoreEvidence, error) {
	evidence.Status = restoreFailed
	classifiedErr := classifyOperation(context.Background(), err)
	evidence.FailureCode = classifiedErr.Error()
	evidence.CompletedAt = time.Now().UTC()
	if service != nil && service.config.Clock != nil {
		evidence.CompletedAt = service.config.Clock().UTC()
	}
	return evidence, classifiedErr
}

func classifyOperation(ctx context.Context, err error) error {
	if errors.Is(ctx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.DeadlineExceeded) || err == interruptedError() || store.Code(err) == "INTERRUPTED" {
		return interruptedError()
	}
	if err == integrityError() || store.Code(err) == "INTEGRITY_FAILURE" {
		return integrityError()
	}
	if err == unsupportedError() || store.Code(err) == "UNSUPPORTED_PLATFORM" {
		return unsupportedError()
	}
	return migrationError()
}

var _ store.MigrationRecovery = (*Service)(nil)

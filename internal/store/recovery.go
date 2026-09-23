package store

import (
	"context"
	"time"
)

type MigrationRecovery interface {
	Prepare(context.Context, MigrationSource, MigrationRequest) (VerifiedSnapshot, error)
	VerifyRestorable(context.Context, MigrationSource, VerifiedSnapshot) (RestoreEvidence, error)
}

type MigrationSource interface {
	OnlineBackup(context.Context, string, BackupStepPolicy) error
	InspectSnapshot(context.Context, string, SnapshotExpectation) (SnapshotInspection, error)
	RestoreSnapshot(context.Context, string, string) error
}

type MigrationRequest struct {
	Purpose              string
	ToolVersion          string
	BuildVersion         string
	CurrentSchemaVersion uint64
	TargetSchemaVersion  uint64
	CatalogSHA256        [32]byte
	CurrentRevision      RevisionToken
	BusyBudget           time.Duration
	RequestedAt          time.Time
}

type VerifiedSnapshot struct {
	SnapshotID    string
	SchemaVersion uint64
	Revision      RevisionToken
	CatalogSHA256 [32]byte
}

type RestoreEvidence struct {
	SnapshotID    string
	Status        string
	SchemaVersion uint64
	Revision      RevisionToken
	StartedAt     time.Time
	CompletedAt   time.Time
	FailureCode   string
}

type BackupStepPolicy struct {
	PagesPerStep int
	BusyBudget   time.Duration
}

type SnapshotExpectation struct {
	SchemaVersion uint64
	Revision      RevisionToken
	CatalogSHA256 [32]byte
}

type SnapshotInspection struct {
	SQLiteVersion   string
	SchemaVersion   uint64
	Revision        RevisionToken
	IntegrityStatus IntegrityStatus
}

// OnlineSnapshotRequest asks the store to produce one consistent read-only
// snapshot of the live control database at a protected destination path, then
// verify its integrity, foreign keys, schema catalog, state revision and
// recovery epoch. It never exposes the live database file to the caller.
type OnlineSnapshotRequest struct {
	Destination string
	Expected    SnapshotExpectation
	BusyBudget  time.Duration
}

// OnlineSnapshotResult is the secret-free description of a consistent snapshot.
type OnlineSnapshotResult struct {
	SQLiteVersion  string
	SchemaVersion  uint64
	Revision       RevisionToken
	CatalogSHA256  [32]byte
	DatabaseSHA256 [32]byte
	Bytes          int64
}

// OnlineSnapshotSource is the store-owned read-only snapshot port consumed by
// the backup capture seam. The backup package never opens the live SQLite file.
// CurrentExpectation reads the live database's current schema version, state
// revision, recovery epoch and migration-catalog digest so the caller can bind
// an exact consistency expectation to the capture; OnlineSnapshot then fails
// closed if the database drifts from it during the copy.
type OnlineSnapshotSource interface {
	CurrentExpectation(context.Context) (SnapshotExpectation, error)
	OnlineSnapshot(context.Context, OnlineSnapshotRequest) (OnlineSnapshotResult, error)
}

// RestoredSQLiteInspector opens only the isolated recovered copy read-only and
// checks its integrity, foreign keys, catalog, revision and recovery epoch.
type RestoredSQLiteInspector interface {
	InspectSnapshot(context.Context, string, SnapshotExpectation) (SnapshotInspection, error)
}

// RestoredSQLiteOwnerInspector applies the same read-only inspection to a
// restored copy owned by the exact execution identity that produced it. This
// does not grant that identity access to the authoritative control database.
type RestoredSQLiteOwnerInspector interface {
	InspectSnapshotOwned(context.Context, string, SnapshotExpectation, uint32) (SnapshotInspection, error)
}

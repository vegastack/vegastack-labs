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
type OnlineSnapshotSource interface {
	OnlineSnapshot(context.Context, OnlineSnapshotRequest) (OnlineSnapshotResult, error)
}

package store

import (
	"context"
	"time"
)

// RevisionToken binds optimistic writes to both the current desired-state
// revision and the active recovery authority.
type RevisionToken struct {
	StateRevision int64
	RecoveryEpoch int64
}

// Commit describes the durable result of one intent transaction.
type Commit struct {
	Changed       bool
	StateRevision int64
	RecoveryEpoch int64
}

type DatabaseMode string

const (
	DatabaseReady    DatabaseMode = "ready"
	DatabaseSafeMode DatabaseMode = "safe-mode"
)

type IntegrityStatus string

const (
	IntegrityUnknown  IntegrityStatus = "unknown"
	IntegrityVerified IntegrityStatus = "verified"
	IntegrityFailed   IntegrityStatus = "failed"
)

type OpenMode string

const (
	OpenExisting  OpenMode = "open-existing"
	InitializeNew OpenMode = "initialize-new"
)

// Health deliberately contains no database path, file identity, SQL text, or
// raw underlying error.
type Health struct {
	Mode                 DatabaseMode
	SchemaVersion        uint64
	SQLiteVersion        string
	Revision             RevisionToken
	MutationEnabled      bool
	RecoveryPending      bool
	IntegrityStatus      IntegrityStatus
	LastIntegrityCheckAt *time.Time
	SafeModeReason       string
}

// ReadTx and IntentTx are intentionally opaque outside this package. Typed
// repositories implemented in internal/store receive the private handles in
// later migrations without exposing database/sql.
type ReadTx struct {
	handle any
}

type IntentTx struct {
	handle  any
	changed bool
}

type IntentStore interface {
	Read(context.Context, func(ReadTx) error) error
	WriteIntent(context.Context, *RevisionToken, func(IntentTx) error) (Commit, error)
}

// FilesystemInspector and MigrationRecovery are closed package ports. Their
// exact methods are defined with their domain types by the lifecycle and
// migration slices; Config prevents callers from bypassing those ports.
type FilesystemInspector interface{}

type Config struct {
	DatabasePath string
	Mode         OpenMode
	BusyTimeout  time.Duration
	ExpectedUID  uint32
	ToolVersion  string
	BuildVersion string
	Clock        func() time.Time
	Filesystem   FilesystemInspector
	Recovery     MigrationRecovery
}

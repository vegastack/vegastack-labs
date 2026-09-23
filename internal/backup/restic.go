package backup

import (
	"context"
	"time"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
)

// ResticRequest describes one exact pinned restic backup invocation. It carries
// only logical references and paths; the repository password is passed
// separately as a borrowed credential value and never appears here.
type ResticRequest struct {
	// Mode is init, config, backup, snapshots, check-full, restore, forget-dry-run, forget or prune.
	// It defaults to backup. Verification modes use a point-bound read lease.
	Mode            string
	BinaryPath      string
	Architecture    string
	RepositoryURL   string
	RepositoryID    string
	RepositoryClass string
	RepositoryRoot  string
	ExchangeRoot    string
	SnapshotPath    string
	SnapshotID      string
	SnapshotIDs     []string
	MaxRepackBytes  int64
	RestoreTarget   string
	PolicyDigest    string
	Lease           WriterLease
	OutputLimit     int64
	// ExecutionUID/GID are fixed by the root-owned custody policy. Zero keeps
	// the current identity for legacy isolated tests only.
	ExecutionUID  uint32
	ExecutionGID  uint32
	ControllerUID uint32
}

// ResticResult is the secret-free description of a completed backup child.
type ResticResult struct {
	SnapshotID       string
	SnapshotCount    int64
	ObjectCount      int64
	ObjectBytes      int64
	Inventory        []ExpectedObject
	SnapshotIDs      []string
	SnapshotPaths    map[string][]string
	RepositoryFormat int
	StartedAt        time.Time
	CompletedAt      time.Time
}

// ResticObservation is a test-only record proving no secret escaped through the
// process arguments, environment, output streams or a temporary file.
type ResticObservation struct {
	Argv             []string
	Env              []string
	Stdout           string
	Stderr           string
	PasswordFileMode string
	TempFileFound    bool
}

// ResticRunner runs the pinned restic child with a sealed anonymous memory
// password FD. Implementations must never place the password in arguments,
// environment, a file, logs or output, and must zero and close the FD on every
// exit path.
type ResticRunner interface {
	Run(ctx context.Context, request ResticRequest, password *credentialref.Value) (ResticResult, error)
	Observation() ResticObservation
}

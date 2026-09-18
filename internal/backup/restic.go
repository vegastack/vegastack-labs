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
	// Mode is "init" (create an empty repository-format-v2 repository) or
	// "backup" (create one snapshot). It defaults to "backup".
	Mode            string
	BinaryPath      string
	Architecture    string
	RepositoryURL   string
	RepositoryID    string
	RepositoryClass string
	RepositoryRoot  string
	SnapshotPath    string
	PolicyDigest    string
	Lease           WriterLease
	OutputLimit     int64
}

// ResticResult is the secret-free description of a completed backup child.
type ResticResult struct {
	SnapshotID       string
	SnapshotCount    int64
	ObjectCount      int64
	ObjectBytes      int64
	Inventory        []ExpectedObject
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

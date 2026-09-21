package backup

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// PolicySource binds one exact canonical backup policy to the source revision,
// recovery epoch and snapshot expectation the capture will enforce. It carries
// no secret material.
type PolicySource struct {
	Policy         generated.BackupPolicy
	PolicyDigest   string
	SourceRevision int64
	RecoveryEpoch  int64
	Expectation    store.SnapshotExpectation
}

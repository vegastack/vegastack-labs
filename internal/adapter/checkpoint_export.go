package adapter

import (
	"context"

	"github.com/vegastack/vegastack-labs/internal/audit"
)

// CheckpointExporter has append-only authority for one exact encrypted object.
// It deliberately exposes no read, delete, list, retention, or lock operation.
type CheckpointExporter interface {
	PutIfAbsent(context.Context, string, []byte, audit.Fingerprint) (audit.ExportReceipt, error)
}

// CheckpointReader is a separate, independently scoped read boundary.
type CheckpointReader interface {
	ReadLast(context.Context, string) (audit.IndependentCheckpoint, error)
}

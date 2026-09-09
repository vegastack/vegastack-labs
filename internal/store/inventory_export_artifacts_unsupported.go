//go:build !linux

package store

import (
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/stateexport"
)

type InventoryExportArtifactConfig struct {
	Root        string
	ExpectedUID uint32
}

func NewInventoryExportArtifactStore(InventoryExportArtifactConfig) (stateexport.ArtifactStore, error) {
	return nil, failure.New("UNSUPPORTED_PLATFORM", "inventory-export-artifacts", false)
}

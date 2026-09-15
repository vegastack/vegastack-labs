//go:build !linux

package store

import (
	"context"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

type GateAttachmentStore struct{}

func NewGateAttachmentStore(string, uint32) (*GateAttachmentStore, error) {
	return nil, newStoreError(generated.ErrorCodeUnsupportedPlatform, "gate-attachments", false, nil)
}
func (*GateAttachmentStore) Put(context.Context, string, []byte) error {
	return newStoreError(generated.ErrorCodeUnsupportedPlatform, "gate-attachments", false, nil)
}
func (*GateAttachmentStore) Get(context.Context, string) ([]byte, error) {
	return nil, newStoreError(generated.ErrorCodeUnsupportedPlatform, "gate-attachments", false, nil)
}

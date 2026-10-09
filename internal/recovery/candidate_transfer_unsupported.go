//go:build !linux

package recovery

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"io"
)

func (r CandidateTransferReceiver) Receive(context.Context, CandidateTransferDescriptor, io.Reader, io.Reader) (PromotionResult, error) {
	return PromotionResult{}, transferFailure(generated.ErrorCodeUnsupportedPlatform)
}

func OpenCandidateTransfer(ctx context.Context, database string, uid uint32, d CandidateTransferDescriptor) (*CandidateTransferSource, error) {
	return nil, transferFailure(generated.ErrorCodePrerequisiteBlocked)
}

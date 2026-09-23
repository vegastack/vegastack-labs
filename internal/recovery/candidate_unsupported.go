//go:build !linux

package recovery

import (
	"context"
	"io"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

type LocalCandidateStorage struct{ ExpectedUID uint32 }

func (LocalCandidateStorage) CreateCandidate(context.Context, CandidatePaths) error {
	return failure.New(generated.ErrorCodeUnsupportedPlatform, "recovery-candidate", false)
}
func (LocalCandidateStorage) VerifyCandidate(context.Context, CandidatePaths) error {
	return failure.New(generated.ErrorCodeUnsupportedPlatform, "recovery-candidate", false)
}
func (LocalCandidateStorage) VerifyPromoted(context.Context, CandidatePaths, StartupExpectation) error {
	return failure.New(generated.ErrorCodeUnsupportedPlatform, "recovery-candidate", false)
}
func (LocalCandidateStorage) ReadTransitionJournal(context.Context, CandidatePaths, string) ([]byte, error) {
	return nil, failure.New(generated.ErrorCodeUnsupportedPlatform, "recovery-candidate", false)
}
func (LocalCandidateStorage) WriteTransitionJournal(context.Context, CandidatePaths, []byte) error {
	return failure.New(generated.ErrorCodeUnsupportedPlatform, "recovery-candidate", false)
}
func (LocalCandidateStorage) AcquireAuthorityLock(context.Context, CandidatePaths) (io.Closer, error) {
	return nil, failure.New(generated.ErrorCodeUnsupportedPlatform, "recovery-candidate", false)
}
func (LocalCandidateStorage) PromoteNoReplace(context.Context, CandidatePaths, StartupExpectation) error {
	return failure.New(generated.ErrorCodeUnsupportedPlatform, "recovery-candidate", false)
}

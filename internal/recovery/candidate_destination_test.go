package recovery

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"testing"
)

func TestReplacementCandidateCannotStageWithoutDestinationResolver(t *testing.T) {
	binding := candidateTestBinding()
	binding.ReplacementContinuity = continuityReference()
	storage := &candidateStorageStub{}
	manager := CandidateManager{DatabasePath: "/var/lib/vsk-labs/control.db", Storage: storage, Authority: &candidateAuthorityStub{}, Records: destinationRecorder{}}
	source := VerifiedSource{Binding: binding.Source, Snapshot: snapshotStub{}, DatabaseDigest: testCandidateDigest("a")}
	if _, err := manager.Stage(context.Background(), binding, source, FenceResult{FenceSetDigest: binding.FenceSetDigest}); err == nil {
		t.Fatal("replacement without actual destination proof staged")
	}
	if storage.created {
		t.Fatal("candidate creation preceded preflight")
	}
}

type destinationRecorder struct{}

func (destinationRecorder) BindRecoveryCandidate(context.Context, generated.RestoreBinding, CandidateReceipt) error {
	return nil
}

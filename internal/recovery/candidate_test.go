package recovery

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

type candidateStorageStub struct {
	live              bool
	created, promoted bool
	journal           []byte
}

func (s *candidateStorageStub) CreateCandidate(context.Context, CandidatePaths) error {
	s.created = true
	return nil
}
func (s *candidateStorageStub) VerifyCandidate(context.Context, CandidatePaths, string) error {
	return nil
}
func (s *candidateStorageStub) WriteTransitionJournal(_ context.Context, _ CandidatePaths, b []byte) error {
	s.journal = append([]byte(nil), b...)
	return nil
}
func (s *candidateStorageStub) AcquireAuthorityLock(context.Context, CandidatePaths) (io.Closer, error) {
	if s.live {
		return nil, errors.New("writer live")
	}
	return io.NopCloser(strings.NewReader("")), nil
}
func (s *candidateStorageStub) PromoteNoReplace(context.Context, CandidatePaths, StartupExpectation) error {
	s.promoted = true
	return nil
}

func TestCandidatePromotionPreservesAuthorityAndNeverCreatesTwoLocalWriters(t *testing.T) {
	storage := &candidateStorageStub{live: true}
	manager := CandidateManager{DatabasePath: "/var/lib/vsk-labs/control.db", Storage: storage}
	expected := StartupExpectation{PlanID: "plan-a", CandidateDigest: "sha256:" + strings.Repeat("a", 64), JournalDigest: "sha256:" + strings.Repeat("b", 64), NewInstanceID: "instance-new", NextRecoveryEpoch: 8}
	if _, err := manager.PromoteAtStartup(context.Background(), expected); err == nil {
		t.Fatal("live writer accepted")
	}
	if storage.promoted {
		t.Fatal("promoted while former writer live")
	}
	storage.live = false
	result, err := manager.PromoteAtStartup(context.Background(), expected)
	if err != nil {
		t.Fatal(err)
	}
	if !result.FormerPreserved || result.InstanceID != "instance-new" || result.RecoveryEpoch != 8 || !storage.promoted {
		t.Fatalf("result=%#v", result)
	}
}

func TestCandidatePathsAreFixedSiblings(t *testing.T) {
	paths, err := DeriveCandidatePaths("/var/lib/vsk-labs/control.db", "plan-a")
	if err != nil {
		t.Fatal(err)
	}
	if paths.Candidate != "/var/lib/vsk-labs/.control.db.recovery-plan-a.candidate" || paths.PreservedAuthority != "/var/lib/vsk-labs/.control.db.recovery-plan-a.former" || paths.AuthorityLock != "/var/lib/vsk-labs/control.db.lock" {
		t.Fatalf("paths=%#v", paths)
	}
	if _, err := DeriveCandidatePaths("relative.db", "plan-a"); err == nil {
		t.Fatal("relative path accepted")
	}
}

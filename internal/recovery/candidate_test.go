package recovery

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

type candidateStorageStub struct {
	live              bool
	candidateMissing  bool
	created, promoted bool
	journal           []byte
}

func (s *candidateStorageStub) CreateCandidate(context.Context, CandidatePaths) error {
	s.created = true
	return nil
}
func (s *candidateStorageStub) VerifyCandidate(context.Context, CandidatePaths) error {
	if s.candidateMissing {
		return errors.New("candidate already promoted")
	}
	return nil
}

func TestCandidatePromotionRestartAcceptsOnlySemanticallyVerifiedActiveAuthority(t *testing.T) {
	binding := candidateTestBinding()
	databaseDigest := testCandidateDigest("6")
	journal, err := candidateTransitionBytes(binding, databaseDigest)
	if err != nil {
		t.Fatal(err)
	}
	storage := &candidateStorageStub{candidateMissing: true, journal: journal}
	authority := &candidateAuthorityStub{}
	manager := CandidateManager{DatabasePath: "/var/lib/vsk-labs/control.db", Storage: storage, Authority: authority}
	result, err := manager.PromoteAtStartup(context.Background(), StartupExpectation{Binding: binding, DatabaseDigest: databaseDigest, JournalDigest: digestBytes(journal)})
	if err != nil {
		t.Fatal(err)
	}
	if !authority.verified || storage.promoted || result.InstanceID != binding.NewInstanceID || result.RecoveryEpoch != binding.NextRecoveryEpoch {
		t.Fatalf("result=%#v verified=%v promoted=%v", result, authority.verified, storage.promoted)
	}
}
func (s *candidateStorageStub) VerifyPromoted(context.Context, CandidatePaths, StartupExpectation) error {
	return nil
}
func (s *candidateStorageStub) WriteTransitionJournal(_ context.Context, _ CandidatePaths, b []byte) error {
	s.journal = append([]byte(nil), b...)
	return nil
}
func (s *candidateStorageStub) ReadTransitionJournal(_ context.Context, _ CandidatePaths, expected string) ([]byte, error) {
	if digestBytes(s.journal) != expected {
		return nil, errors.New("journal digest mismatch")
	}
	return append([]byte(nil), s.journal...), nil
}
func (s *candidateStorageStub) AcquireAuthorityLock(context.Context, CandidatePaths) (io.Closer, error) {
	if s.live {
		return nil, errors.New("writer live")
	}
	return io.NopCloser(strings.NewReader("")), nil
}

type candidateAuthorityStub struct{ verified bool }

func (*candidateAuthorityStub) PrepareRecoveredAuthority(context.Context, string, generated.RestoreBinding, AuditContinuity) error {
	return nil
}
func (stub *candidateAuthorityStub) VerifyRecoveredAuthority(context.Context, string, generated.RestoreBinding) error {
	stub.verified = true
	return nil
}
func (s *candidateStorageStub) PromoteNoReplace(context.Context, CandidatePaths, StartupExpectation) error {
	s.promoted = true
	return nil
}

func TestCandidatePromotionPreservesAuthorityAndNeverCreatesTwoLocalWriters(t *testing.T) {
	storage := &candidateStorageStub{live: true}
	authority := &candidateAuthorityStub{}
	manager := CandidateManager{DatabasePath: "/var/lib/vsk-labs/control.db", Storage: storage, Authority: authority}
	binding := candidateTestBinding()
	journal, err := candidateTransitionBytes(binding, testCandidateDigest("6"))
	if err != nil {
		t.Fatal(err)
	}
	storage.journal = journal
	expected := StartupExpectation{Binding: binding, DatabaseDigest: testCandidateDigest("6"), JournalDigest: digestBytes(journal)}
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
	if !result.FormerPreserved || result.InstanceID != binding.NewInstanceID || result.RecoveryEpoch != binding.NextRecoveryEpoch || !storage.promoted || !authority.verified {
		t.Fatalf("result=%#v", result)
	}
}

func TestCandidatePromotionRejectsAnySemanticBindingChange(t *testing.T) {
	binding := candidateTestBinding()
	databaseDigest := testCandidateDigest("6")
	journal, err := candidateTransitionBytes(binding, databaseDigest)
	if err != nil {
		t.Fatal(err)
	}
	storage := &candidateStorageStub{journal: journal}
	manager := CandidateManager{DatabasePath: "/var/lib/vsk-labs/control.db", Storage: storage, Authority: &candidateAuthorityStub{}}
	expected := StartupExpectation{Binding: binding, DatabaseDigest: databaseDigest, JournalDigest: digestBytes(journal)}
	expected.Binding.FenceSetDigest = testCandidateDigest("7")
	if _, err := manager.PromoteAtStartup(context.Background(), expected); err == nil {
		t.Fatal("changed semantic binding accepted")
	}
	if storage.promoted {
		t.Fatal("candidate promoted after binding change")
	}
}

func TestCandidatePathsAreFixedSiblings(t *testing.T) {
	paths, err := DeriveCandidatePaths("/var/lib/vsk-labs/control.db", "plan-a")
	if err != nil {
		t.Fatal(err)
	}
	if paths.Candidate != "/var/lib/vsk-labs/.control.db.recovery-plan-a.candidate" || paths.PreservedAuthority != "/var/lib/vsk-labs/.control.db.recovery-plan-a.former" || paths.TransitionJournal != "/var/lib/vsk-labs/.control.db.recovery-plan-a.journal" || paths.AuthorityLock != "/var/lib/vsk-labs/control.db.lock" {
		t.Fatalf("paths=%#v", paths)
	}
	if _, err := DeriveCandidatePaths("relative.db", "plan-a"); err == nil {
		t.Fatal("relative path accepted")
	}
}

func candidateTestBinding() generated.RestoreBinding {
	source := generated.RestoreSourceBinding{Schema: generated.SchemaIDRestoreSourceBinding, SchemaVersion: "1.1.0", PointID: "point-a", PointDigest: testCandidateDigest("1"), ManifestDigest: testCandidateDigest("2"), VerificationDigest: testCandidateDigest("3"), SourceClass: "local", RepositoryGenerationID: "generation-a", DeclaredRPOSeconds: 3600, CreatedAt: "2026-09-24T05:00:00Z", VerifiedAt: "2026-09-24T05:30:00Z", RecoveryEpoch: 7, DependencyDigests: []string{testCandidateDigest("4")}}
	return generated.RestoreBinding{Schema: generated.SchemaIDRestoreBinding, SchemaVersion: "1.1.0", Source: source, PointID: source.PointID, DependencyIDs: []string{"dependency-a"}, TargetIDs: []string{"control-a"}, TargetDigest: testCandidateDigest("5"), PlanID: "plan-a", PlanDigest: testCandidateDigest("a"), HumanAcknowledgementID: "ack-a", FenceSetDigest: testCandidateDigest("b"), AuditDecisionDigest: testCandidateDigest("c"), CandidateDigest: testCandidateDigest("d"), PriorInstanceID: "instance-old", NewInstanceID: "instance-new", PriorRecoveryEpoch: 7, NextRecoveryEpoch: 8, Status: "planned"}
}

func testCandidateDigest(letter string) string { return "sha256:" + strings.Repeat(letter, 64) }

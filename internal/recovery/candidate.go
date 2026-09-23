package recovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"path/filepath"
	"regexp"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

var candidatePlanID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type CandidatePaths struct{ Candidate, PreservedAuthority, TransitionJournal, AuthorityLock string }
type candidateTarget struct{ path string }

func (candidateTarget) recoveryCandidateTarget() {}

type CandidateReceipt struct {
	PlanID, CandidateDigest, JournalDigest, NewInstanceID string
	NextRecoveryEpoch                                     int64
}

type StartupExpectation struct {
	PlanID, CandidateDigest, JournalDigest, NewInstanceID string
	NextRecoveryEpoch                                     int64
}

type PromotionResult struct {
	FormerPreserved bool
	InstanceID      string
	RecoveryEpoch   int64
}

type CandidateStorage interface {
	CreateCandidate(context.Context, CandidatePaths) error
	VerifyCandidate(context.Context, CandidatePaths, string) error
	WriteTransitionJournal(context.Context, CandidatePaths, []byte) error
	AcquireAuthorityLock(context.Context, CandidatePaths) (io.Closer, error)
	PromoteNoReplace(context.Context, CandidatePaths, StartupExpectation) error
}

type CandidateRecorder interface {
	BindRecoveryCandidate(context.Context, generated.RestoreBinding, CandidateReceipt) error
}

type CandidateManager struct {
	DatabasePath string
	Storage      CandidateStorage
	Records      CandidateRecorder
}

func DeriveCandidatePaths(databasePath, planID string) (CandidatePaths, error) {
	if !filepath.IsAbs(databasePath) || filepath.Clean(databasePath) != databasePath || !candidatePlanID.MatchString(planID) {
		return CandidatePaths{}, failure.New(generated.ErrorCodeInputInvalid, "recovery-candidate-path", false)
	}
	directory, base := filepath.Dir(databasePath), filepath.Base(databasePath)
	prefix := filepath.Join(directory, "."+base+".recovery-"+planID)
	return CandidatePaths{Candidate: prefix + ".candidate", PreservedAuthority: prefix + ".former", TransitionJournal: prefix + ".journal", AuthorityLock: databasePath + ".lock"}, nil
}

// CandidateTargetPath is the sole path disclosure to a snapshot resolver. The
// resolver cannot construct a target and therefore cannot redirect a restore.
func CandidateTargetPath(target CandidateTarget) (string, bool) {
	value, ok := target.(candidateTarget)
	return value.path, ok && value.path != ""
}

func (manager CandidateManager) Stage(ctx context.Context, binding generated.RestoreBinding, source VerifiedSource, fence FenceResult) (CandidateReceipt, error) {
	blocked := func(target string) (CandidateReceipt, error) {
		return CandidateReceipt{}, failure.New(generated.ErrorCodePrerequisiteBlocked, target, false)
	}
	if ctx == nil || ctx.Err() != nil || manager.Storage == nil || manager.Records == nil || source.Snapshot == nil || binding.SchemaVersion != "1.1.0" || binding.Status != "inert" || binding.PlanID == "" || binding.PointID != source.Binding.PointID || !sameRestoreSource(binding.Source, source.Binding) || binding.FenceSetDigest != fence.FenceSetDigest || binding.PriorRecoveryEpoch != source.Binding.RecoveryEpoch || binding.NextRecoveryEpoch != binding.PriorRecoveryEpoch+1 || binding.PriorInstanceID == "" || binding.NewInstanceID == "" || binding.PriorInstanceID == binding.NewInstanceID || !restoreDigest.MatchString(binding.CandidateDigest) || !restoreDigest.MatchString(binding.AuditDecisionDigest) {
		return blocked("recovery-candidate")
	}
	paths, err := DeriveCandidatePaths(manager.DatabasePath, binding.PlanID)
	if err != nil {
		return CandidateReceipt{}, err
	}
	if err := manager.Storage.CreateCandidate(ctx, paths); err != nil {
		return CandidateReceipt{}, err
	}
	snapshot, err := source.Snapshot.Restore(ctx, candidateTarget{path: paths.Candidate})
	if err != nil || snapshot.PointID != binding.PointID || snapshot.ContentDigest != source.DatabaseDigest {
		return blocked("recovery-candidate-restore")
	}
	if err := manager.Storage.VerifyCandidate(ctx, paths, binding.CandidateDigest); err != nil {
		return CandidateReceipt{}, err
	}
	journal := struct {
		Domain                         string
		Binding                        generated.RestoreBinding
		FenceSetDigest, DatabaseDigest string
	}{"vegastack-labs.dev/recovery-transition/v1", binding, fence.FenceSetDigest, source.DatabaseDigest}
	raw, err := json.Marshal(journal)
	if err != nil {
		return blocked("recovery-candidate-journal")
	}
	sum := sha256.Sum256(raw)
	journalDigest := "sha256:" + hex.EncodeToString(sum[:])
	if err := manager.Storage.WriteTransitionJournal(ctx, paths, raw); err != nil {
		return CandidateReceipt{}, err
	}
	receipt := CandidateReceipt{PlanID: binding.PlanID, CandidateDigest: binding.CandidateDigest, JournalDigest: journalDigest, NewInstanceID: binding.NewInstanceID, NextRecoveryEpoch: binding.NextRecoveryEpoch}
	if err := manager.Records.BindRecoveryCandidate(ctx, binding, receipt); err != nil {
		return CandidateReceipt{}, err
	}
	return receipt, nil
}

func (manager CandidateManager) PromoteAtStartup(ctx context.Context, expected StartupExpectation) (PromotionResult, error) {
	if ctx == nil || ctx.Err() != nil || manager.Storage == nil || !candidatePlanID.MatchString(expected.PlanID) || !restoreDigest.MatchString(expected.CandidateDigest) || !restoreDigest.MatchString(expected.JournalDigest) || expected.NewInstanceID == "" || expected.NextRecoveryEpoch < 1 {
		return PromotionResult{}, failure.New(generated.ErrorCodePrerequisiteBlocked, "recovery-promotion", false)
	}
	paths, err := DeriveCandidatePaths(manager.DatabasePath, expected.PlanID)
	if err != nil {
		return PromotionResult{}, err
	}
	lock, err := manager.Storage.AcquireAuthorityLock(ctx, paths)
	if err != nil {
		return PromotionResult{}, err
	}
	defer lock.Close()
	if err := manager.Storage.VerifyCandidate(ctx, paths, expected.CandidateDigest); err != nil {
		return PromotionResult{}, err
	}
	if err := manager.Storage.PromoteNoReplace(ctx, paths, expected); err != nil {
		return PromotionResult{}, err
	}
	return PromotionResult{FormerPreserved: true, InstanceID: expected.NewInstanceID, RecoveryEpoch: expected.NextRecoveryEpoch}, nil
}

func sameRestoreSource(left, right generated.RestoreSourceBinding) bool {
	a, _ := json.Marshal(left)
	b, _ := json.Marshal(right)
	return string(a) == string(b)
}

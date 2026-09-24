package recovery

import (
	"bytes"
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
	PlanID, CandidateDigest, DatabaseDigest, JournalDigest, BundleDigest, NewInstanceID string
	NextRecoveryEpoch                                                                   int64
}

type StartupExpectation struct {
	Binding        generated.RestoreBinding
	DatabaseDigest string
	JournalDigest  string
	BundleDigest   string
}

type PromotionResult struct {
	FormerPreserved bool
	InstanceID      string
	RecoveryEpoch   int64
}

type CandidateStorage interface {
	CreateCandidate(context.Context, CandidatePaths) error
	VerifyCandidate(context.Context, CandidatePaths) error
	VerifyPromoted(context.Context, CandidatePaths, StartupExpectation) error
	WriteTransitionJournal(context.Context, CandidatePaths, []byte) error
	ReadTransitionJournal(context.Context, CandidatePaths, string) ([]byte, error)
	AcquireAuthorityLock(context.Context, CandidatePaths) (io.Closer, error)
	PromoteNoReplace(context.Context, CandidatePaths, StartupExpectation) error
}

type CandidateRecorder interface {
	BindRecoveryCandidate(context.Context, generated.RestoreBinding, CandidateReceipt) error
}

type CandidateAuthority interface {
	PrepareRecoveredAuthority(context.Context, string, generated.RestoreBinding, AuditContinuity) error
	VerifyRecoveredAuthority(context.Context, string, generated.RestoreBinding) error
}

type CandidateBundleStore interface {
	WriteRecoveryBundle(context.Context, string, generated.RestoreBinding) (string, error)
	VerifyRecoveryBundle(context.Context, string, generated.RestoreBinding, string) error
}

type CandidateManager struct {
	DatabasePath string
	Storage      CandidateStorage
	Records      CandidateRecorder
	Authority    CandidateAuthority
	Bundles      CandidateBundleStore
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
	if ctx == nil || ctx.Err() != nil || manager.Storage == nil || manager.Records == nil || manager.Authority == nil || source.Snapshot == nil || binding.SchemaVersion != "1.1.0" || binding.Status != "planned" || binding.PlanID == "" || binding.PointID != source.Binding.PointID || !sameRestoreSource(binding.Source, source.Binding) || binding.FenceSetDigest != fence.FenceSetDigest || binding.PriorRecoveryEpoch != source.Binding.RecoveryEpoch || binding.NextRecoveryEpoch != binding.PriorRecoveryEpoch+1 || binding.PriorInstanceID == "" || binding.NewInstanceID == "" || binding.PriorInstanceID == binding.NewInstanceID || !restoreDigest.MatchString(binding.CandidateDigest) || !restoreDigest.MatchString(binding.AuditDecisionDigest) {
		return blocked("recovery-candidate")
	}
	paths, err := DeriveCandidatePaths(manager.DatabasePath, binding.PlanID)
	if err != nil {
		return CandidateReceipt{}, err
	}
	if err := manager.Storage.CreateCandidate(ctx, paths); err != nil {
		return CandidateReceipt{}, err
	}
	snapshot, err := source.Snapshot.Restore(ctx, candidateTarget{path: paths.Candidate}, binding)
	if err != nil || snapshot.PointID != binding.PointID || snapshot.ContentDigest != source.DatabaseDigest {
		return blocked("recovery-candidate-restore")
	}
	if err := manager.Authority.PrepareRecoveredAuthority(ctx, paths.Candidate, binding, source.Audit); err != nil {
		return CandidateReceipt{}, err
	}
	bundleDigest := ""
	if manager.Bundles != nil {
		bundleDigest, err = manager.Bundles.WriteRecoveryBundle(ctx, paths.Candidate, binding)
		if err != nil || !restoreDigest.MatchString(bundleDigest) {
			return blocked("recovery-candidate-bundle")
		}
	}
	if err := manager.Storage.VerifyCandidate(ctx, paths); err != nil {
		return CandidateReceipt{}, err
	}
	if err := manager.Authority.VerifyRecoveredAuthority(ctx, paths.Candidate, binding); err != nil {
		return CandidateReceipt{}, err
	}
	raw, err := candidateTransitionBytes(binding, source.DatabaseDigest)
	if err != nil {
		return blocked("recovery-candidate-journal")
	}
	sum := sha256.Sum256(raw)
	journalDigest := "sha256:" + hex.EncodeToString(sum[:])
	if err := manager.Storage.WriteTransitionJournal(ctx, paths, raw); err != nil {
		return CandidateReceipt{}, err
	}
	receipt := CandidateReceipt{PlanID: binding.PlanID, CandidateDigest: binding.CandidateDigest, DatabaseDigest: source.DatabaseDigest, JournalDigest: journalDigest, BundleDigest: bundleDigest, NewInstanceID: binding.NewInstanceID, NextRecoveryEpoch: binding.NextRecoveryEpoch}
	if err := manager.Records.BindRecoveryCandidate(ctx, binding, receipt); err != nil {
		return CandidateReceipt{}, err
	}
	return receipt, nil
}

func (manager CandidateManager) PromoteAtStartup(ctx context.Context, expected StartupExpectation) (PromotionResult, error) {
	binding := expected.Binding
	if ctx == nil || ctx.Err() != nil || manager.Storage == nil || manager.Authority == nil || !validCandidateBinding(binding) || !restoreDigest.MatchString(expected.DatabaseDigest) || !restoreDigest.MatchString(expected.JournalDigest) {
		return PromotionResult{}, failure.New(generated.ErrorCodePrerequisiteBlocked, "recovery-promotion", false)
	}
	paths, err := DeriveCandidatePaths(manager.DatabasePath, binding.PlanID)
	if err != nil {
		return PromotionResult{}, err
	}
	lock, err := manager.Storage.AcquireAuthorityLock(ctx, paths)
	if err != nil {
		return PromotionResult{}, err
	}
	defer func() {
		if lock != nil {
			_ = lock.Close()
		}
	}()
	journal, err := manager.Storage.ReadTransitionJournal(ctx, paths, expected.JournalDigest)
	if err != nil {
		return PromotionResult{}, err
	}
	want, err := candidateTransitionBytes(binding, expected.DatabaseDigest)
	if err != nil || !bytes.Equal(journal, want) {
		return PromotionResult{}, failure.New(generated.ErrorCodeIntegrityFailure, "recovery-candidate-binding", false)
	}
	if err := manager.Storage.VerifyCandidate(ctx, paths); err != nil {
		if promotedErr := manager.Storage.VerifyPromoted(ctx, paths, expected); promotedErr != nil {
			return PromotionResult{}, err
		}
		// The promoted database uses the same writer-lock path as this startup
		// transition. Release the transition lock before the store opener takes
		// that lock for semantic verification. A competing process that wins the
		// handoff keeps this process fail-closed at Store.Open.
		if closeErr := lock.Close(); closeErr != nil {
			return PromotionResult{}, closeErr
		}
		lock = nil
		if verifyErr := manager.Authority.VerifyRecoveredAuthority(ctx, manager.DatabasePath, binding); verifyErr != nil {
			return PromotionResult{}, verifyErr
		}
		if expected.BundleDigest != "" && (manager.Bundles == nil || manager.Bundles.VerifyRecoveryBundle(ctx, manager.DatabasePath, binding, expected.BundleDigest) != nil) {
			return PromotionResult{}, failure.New(generated.ErrorCodeIntegrityFailure, "recovery-candidate-bundle", false)
		}
		return PromotionResult{FormerPreserved: true, InstanceID: binding.NewInstanceID, RecoveryEpoch: binding.NextRecoveryEpoch}, nil
	}
	if err := manager.Authority.VerifyRecoveredAuthority(ctx, paths.Candidate, binding); err != nil {
		return PromotionResult{}, err
	}
	if expected.BundleDigest != "" && (manager.Bundles == nil || manager.Bundles.VerifyRecoveryBundle(ctx, paths.Candidate, binding, expected.BundleDigest) != nil) {
		return PromotionResult{}, failure.New(generated.ErrorCodeIntegrityFailure, "recovery-candidate-bundle", false)
	}
	if err := manager.Storage.PromoteNoReplace(ctx, paths, expected); err != nil {
		return PromotionResult{}, err
	}
	return PromotionResult{FormerPreserved: true, InstanceID: binding.NewInstanceID, RecoveryEpoch: binding.NextRecoveryEpoch}, nil
}

type candidateTransition struct {
	Domain         string                   `json:"domain"`
	Binding        generated.RestoreBinding `json:"binding"`
	DatabaseDigest string                   `json:"databaseDigest"`
}

// candidateTransitionBytes is the deterministic semantic identity of a staged
// candidate. CandidateDigest remains the plan-declared artifact identity; the
// transition digest binds it to the exact plan, source, fences, audit decision,
// and replacement authority without pretending mutable SQLite bytes are stable.
func candidateTransitionBytes(binding generated.RestoreBinding, databaseDigest string) ([]byte, error) {
	if !validCandidateBinding(binding) || !restoreDigest.MatchString(databaseDigest) {
		return nil, failure.New(generated.ErrorCodePrerequisiteBlocked, "recovery-candidate-binding", false)
	}
	return json.Marshal(candidateTransition{Domain: "vegastack-labs.dev/recovery-transition/v1", Binding: binding, DatabaseDigest: databaseDigest})
}

func validCandidateBinding(binding generated.RestoreBinding) bool {
	raw, err := json.Marshal(binding)
	return err == nil && generated.ValidateContractJSON(generated.SchemaIDRestoreBinding, raw, generated.ContractExact) == nil &&
		candidatePlanID.MatchString(binding.PlanID) && restoreDigest.MatchString(binding.PlanDigest) && restoreDigest.MatchString(binding.CandidateDigest) &&
		restoreDigest.MatchString(binding.FenceSetDigest) && restoreDigest.MatchString(binding.AuditDecisionDigest) && binding.PointID == binding.Source.PointID &&
		binding.PriorInstanceID != "" && binding.NewInstanceID != "" && binding.PriorInstanceID != binding.NewInstanceID && binding.NextRecoveryEpoch == binding.PriorRecoveryEpoch+1 && binding.Status == "planned"
}

func sameRestoreSource(left, right generated.RestoreSourceBinding) bool {
	a, _ := json.Marshal(left)
	b, _ := json.Marshal(right)
	return string(a) == string(b)
}

func digestBytes(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

//go:build linux

package recovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"golang.org/x/sys/unix"
)

type LocalCandidateStorage struct{ ExpectedUID uint32 }

func (storage LocalCandidateStorage) CreateCandidate(ctx context.Context, paths CandidatePaths) error {
	if err := ctx.Err(); err != nil {
		return failure.New(generated.ErrorCodeInterrupted, "recovery-candidate", false)
	}
	if err := secureRecoveryParent(paths.Candidate, storage.ExpectedUID); err != nil {
		return err
	}
	for _, path := range []string{paths.Candidate, paths.PreservedAuthority, paths.TransitionJournal} {
		if _, err := os.Lstat(path); err == nil {
			return failure.New(generated.ErrorCodeStateConflict, "recovery-candidate", false)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return failure.New(generated.ErrorCodeIntegrityFailure, "recovery-candidate", false)
		}
	}
	return nil
}

func (storage LocalCandidateStorage) VerifyCandidate(ctx context.Context, paths CandidatePaths) error {
	if err := ctx.Err(); err != nil {
		return failure.New(generated.ErrorCodeInterrupted, "recovery-candidate", false)
	}
	return verifyRecoveryFile(paths.Candidate, storage.ExpectedUID, "", false)
}

func (storage LocalCandidateStorage) VerifyPromoted(ctx context.Context, paths CandidatePaths, expected StartupExpectation) error {
	if err := ctx.Err(); err != nil {
		return failure.New(generated.ErrorCodeInterrupted, "recovery-promotion", false)
	}
	if _, err := os.Lstat(paths.Candidate); !errors.Is(err, fs.ErrNotExist) {
		return failure.New(generated.ErrorCodeStateConflict, "recovery-promotion", false)
	}
	active := filepath.Join(filepath.Dir(paths.Candidate), stringsTrimCandidateBase(filepath.Base(paths.Candidate), expected.Binding.PlanID))
	if err := verifyRecoveryFile(active, storage.ExpectedUID, "", false); err != nil {
		return err
	}
	if err := verifyRecoveryFile(paths.PreservedAuthority, storage.ExpectedUID, "", false); err != nil {
		return err
	}
	if err := verifyRecoveryFile(paths.TransitionJournal, storage.ExpectedUID, expected.JournalDigest, false); err != nil {
		return err
	}
	return syncRecoveryDirectory(filepath.Dir(paths.Candidate))
}

func (storage LocalCandidateStorage) WriteTransitionJournal(ctx context.Context, paths CandidatePaths, body []byte) error {
	if err := ctx.Err(); err != nil || len(body) == 0 {
		return failure.New(generated.ErrorCodeInterrupted, "recovery-journal", false)
	}
	file, err := os.OpenFile(paths.TransitionJournal, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return failure.New(generated.ErrorCodeStateConflict, "recovery-journal", false)
	}
	_, writeErr := file.Write(body)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return failure.New(generated.ErrorCodeIntegrityFailure, "recovery-journal", false)
	}
	if err := verifyRecoveryFile(paths.TransitionJournal, storage.ExpectedUID, digestBytes(body), false); err != nil {
		return err
	}
	return syncRecoveryDirectory(filepath.Dir(paths.TransitionJournal))
}

func (storage LocalCandidateStorage) ReadTransitionJournal(ctx context.Context, paths CandidatePaths, expected string) ([]byte, error) {
	if err := ctx.Err(); err != nil || !restoreDigest.MatchString(expected) {
		return nil, failure.New(generated.ErrorCodeInterrupted, "recovery-journal", false)
	}
	if err := verifyRecoveryFile(paths.TransitionJournal, storage.ExpectedUID, expected, false); err != nil {
		return nil, err
	}
	body, err := os.ReadFile(paths.TransitionJournal)
	if err != nil {
		return nil, failure.New(generated.ErrorCodeIntegrityFailure, "recovery-journal", false)
	}
	return body, nil
}

func (storage LocalCandidateStorage) AcquireAuthorityLock(ctx context.Context, paths CandidatePaths) (io.Closer, error) {
	if err := ctx.Err(); err != nil {
		return nil, failure.New(generated.ErrorCodeInterrupted, "recovery-authority-lock", false)
	}
	fd, err := unix.Open(paths.AuthorityLock, unix.O_CLOEXEC|unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, failure.New(generated.ErrorCodeIntegrityFailure, "recovery-authority-lock", false)
	}
	file := os.NewFile(uintptr(fd), "recovery-authority-lock")
	if file == nil {
		unix.Close(fd)
		return nil, failure.New(generated.ErrorCodeIntegrityFailure, "recovery-authority-lock", false)
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Sys().(*syscall.Stat_t).Uid != storage.ExpectedUID || info.Sys().(*syscall.Stat_t).Nlink != 1 {
		file.Close()
		return nil, failure.New(generated.ErrorCodeIntegrityFailure, "recovery-authority-lock", false)
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		file.Close()
		return nil, failure.New(generated.ErrorCodeStateConflict, "recovery-authority-lock", true)
	}
	return &candidateLock{file: file}, nil
}

func (storage LocalCandidateStorage) PromoteNoReplace(ctx context.Context, paths CandidatePaths, expected StartupExpectation) error {
	if err := ctx.Err(); err != nil {
		return failure.New(generated.ErrorCodeInterrupted, "recovery-promotion", false)
	}
	if err := verifyRecoveryFile(paths.Candidate, storage.ExpectedUID, "", false); err != nil {
		return err
	}
	if err := verifyRecoveryFile(paths.TransitionJournal, storage.ExpectedUID, expected.JournalDigest, false); err != nil {
		return err
	}
	directory := filepath.Dir(paths.Candidate)
	active := filepath.Join(directory, stringsTrimCandidateBase(filepath.Base(paths.Candidate), expected.Binding.PlanID))
	if _, err := os.Lstat(paths.PreservedAuthority); errors.Is(err, fs.ErrNotExist) {
		if err := verifyRecoveryFile(active, storage.ExpectedUID, "", true); err != nil {
			return err
		}
		if err := unix.Renameat2(unix.AT_FDCWD, active, unix.AT_FDCWD, paths.PreservedAuthority, unix.RENAME_NOREPLACE); err != nil {
			return failure.New(generated.ErrorCodeStateConflict, "recovery-preserve", false)
		}
		if err := syncRecoveryDirectory(directory); err != nil {
			return err
		}
	} else if err != nil {
		return failure.New(generated.ErrorCodeIntegrityFailure, "recovery-preserve", false)
	} else if _, err := os.Lstat(active); err == nil {
		return failure.New(generated.ErrorCodeStateConflict, "recovery-preserve", false)
	}
	if err := unix.Renameat2(unix.AT_FDCWD, paths.Candidate, unix.AT_FDCWD, active, unix.RENAME_NOREPLACE); err != nil {
		return failure.New(generated.ErrorCodeStateConflict, "recovery-promote", false)
	}
	return syncRecoveryDirectory(directory)
}

func stringsTrimCandidateBase(name, planID string) string {
	return name[len(".") : len(name)-len(".recovery-"+planID+".candidate")]
}
func secureRecoveryParent(path string, uid uint32) error {
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return failure.New(generated.ErrorCodeIntegrityFailure, "recovery-directory", false)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uid {
		return failure.New(generated.ErrorCodeIntegrityFailure, "recovery-directory", false)
	}
	return nil
}
func verifyRecoveryFile(path string, uid uint32, expected string, allowEmpty bool) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return failure.New(generated.ErrorCodeIntegrityFailure, "recovery-file", false)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uid || stat.Nlink != 1 || (!allowEmpty && info.Size() == 0) {
		return failure.New(generated.ErrorCodeIntegrityFailure, "recovery-file", false)
	}
	if expected != "" {
		file, err := os.Open(path)
		if err != nil {
			return failure.New(generated.ErrorCodeIntegrityFailure, "recovery-file", false)
		}
		hash := sha256.New()
		_, copyErr := io.Copy(hash, file)
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil || "sha256:"+hex.EncodeToString(hash.Sum(nil)) != expected {
			return failure.New(generated.ErrorCodeIntegrityFailure, "recovery-file-digest", false)
		}
	}
	return nil
}
func syncRecoveryDirectory(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return failure.New(generated.ErrorCodeIntegrityFailure, "recovery-directory", false)
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	if syncErr != nil || closeErr != nil {
		return failure.New(generated.ErrorCodeIntegrityFailure, "recovery-directory", false)
	}
	return nil
}

type candidateLock struct{ file *os.File }

func (lock *candidateLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	_ = unix.Flock(int(lock.file.Fd()), unix.LOCK_UN)
	return lock.file.Close()
}

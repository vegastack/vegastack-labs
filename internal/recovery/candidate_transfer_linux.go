//go:build linux

package recovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"golang.org/x/sys/unix"
)

// Receive verifies and promotes only a fresh destination. On any interruption,
// exact partial files remain and a later receive refuses them; no retry framework
// or invented former database is created. The resulting authority stays in the
// existing recovery-required state until the ordinary canary enables it.
func (r CandidateTransferReceiver) Receive(ctx context.Context, d CandidateTransferDescriptor, candidate, journal io.Reader) (PromotionResult, error) {
	var out PromotionResult
	if ctx == nil || ctx.Err() != nil || candidate == nil || journal == nil || uint32(os.Geteuid()) != r.ExpectedUID || int64(r.ExpectedUID) != d.ServiceUID || r.Authority == nil || r.Bundles == nil || r.Destination == nil || validateCandidateTransfer(d) != nil {
		return out, transferFailure(generated.ErrorCodePrerequisiteBlocked)
	}
	paths, e := DeriveCandidatePaths(r.DatabasePath, d.Binding.PlanID)
	if e != nil {
		return out, e
	}
	if e = secureRecoveryParent(paths.Candidate, r.ExpectedUID); e != nil {
		return out, e
	}
	// Identity and role preimages are measured before creating even a lock file.
	if e = r.Destination.VerifyCandidateTransferDestination(ctx, d); e != nil {
		return out, e
	}
	if e = absentColdCandidate(r.DatabasePath, paths); e != nil {
		return out, e
	}
	lock, e := os.OpenFile(paths.AuthorityLock, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if e != nil {
		return out, transferFailure(generated.ErrorCodeStateConflict)
	}
	defer lock.Close()
	if unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		return out, transferFailure(generated.ErrorCodeStateConflict)
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	if e = transferFile(ctx, paths.Candidate, r.ExpectedUID, d.CandidateBytes, d.CandidateBytesDigest, candidate); e != nil {
		return out, e
	}
	if e = transferFile(ctx, paths.TransitionJournal, r.ExpectedUID, d.JournalBytes, d.JournalDigest, journal); e != nil {
		return out, e
	}
	if e = syncRecoveryDirectory(filepath.Dir(r.DatabasePath)); e != nil {
		return out, e
	}
	if e = r.Authority.VerifyRecoveredAuthority(ctx, paths.Candidate, d.Binding); e != nil {
		return out, e
	}
	if e = r.Bundles.VerifyRecoveryBundle(ctx, paths.Candidate, d.Binding, d.BundleDigest); e != nil {
		return out, e
	}
	// Recheck physical destination and protected preimages after streaming and
	// semantic verification, immediately before the no-replace promotion.
	if e = r.Destination.VerifyCandidateTransferDestination(ctx, d); e != nil {
		return out, e
	}
	for _, p := range []string{r.DatabasePath, r.DatabasePath + "-wal", r.DatabasePath + "-shm", r.DatabasePath + "-journal", paths.PreservedAuthority, paths.Candidate + "-wal", paths.Candidate + "-shm", paths.Candidate + "-journal"} {
		if _, e = os.Lstat(p); !errors.Is(e, os.ErrNotExist) {
			return out, transferFailure(generated.ErrorCodeStateConflict)
		}
	}
	if e = unix.Renameat2(unix.AT_FDCWD, paths.Candidate, unix.AT_FDCWD, r.DatabasePath, unix.RENAME_NOREPLACE); e != nil {
		return out, transferFailure(generated.ErrorCodeStateConflict)
	}
	if e = syncRecoveryDirectory(filepath.Dir(r.DatabasePath)); e != nil {
		return out, e
	}
	return PromotionResult{FormerPreserved: false, InstanceID: d.Binding.NewInstanceID, RecoveryEpoch: d.Binding.NextRecoveryEpoch}, nil
}
func absentColdCandidate(database string, p CandidatePaths) error {
	paths := []string{database, database + "-wal", database + "-shm", database + "-journal", p.AuthorityLock, p.Candidate, p.Candidate + "-wal", p.Candidate + "-shm", p.Candidate + ".lock", p.PreservedAuthority, p.TransitionJournal}
	if database == "/var/lib/vsk-labs/control/control.db" {
		paths = append(paths, "/var/lib/vsk-labs/control.db", "/var/lib/vsk-labs/control.db-wal", "/var/lib/vsk-labs/control.db-shm", "/var/lib/vsk-labs/control.db.lock")
	}
	for _, path := range paths {
		if _, e := os.Lstat(path); !errors.Is(e, os.ErrNotExist) {
			return transferFailure(generated.ErrorCodeStateConflict)
		}
	}
	return nil
}
func transferFile(ctx context.Context, path string, uid uint32, size int64, want string, source io.Reader) error {
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return transferFailure(generated.ErrorCodeStateConflict)
	}
	defer f.Close()
	i, e := f.Stat()
	if e != nil {
		return e
	}
	st, ok := i.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uid || st.Nlink != 1 {
		return transferFailure(generated.ErrorCodeIntegrityFailure)
	}
	h := sha256.New()
	n, e := io.CopyN(io.MultiWriter(f, h), contextTransferReader{ctx, source}, size)
	if e != nil || n != size || "sha256:"+hex.EncodeToString(h.Sum(nil)) != want {
		return transferFailure(generated.ErrorCodeIntegrityFailure)
	}
	// Each transport supplies an exact length-limited stream. An extra byte is
	// a framing violation, never silently ignored before the next artifact.
	var extra [1]byte
	n2, e := source.Read(extra[:])
	if n2 != 0 || e != io.EOF {
		return transferFailure(generated.ErrorCodeIntegrityFailure)
	}
	if e = f.Sync(); e != nil {
		return transferFailure(generated.ErrorCodeIntegrityFailure)
	}
	return nil
}

type contextTransferReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextTransferReader) Read(p []byte) (int, error) {
	if e := r.ctx.Err(); e != nil {
		return 0, e
	}
	return r.r.Read(p)
}

//go:build linux

package recovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"syscall"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

// OpenCandidateTransfer opens only the fixed server-owned staged files. The
// caller resolves the pending binding and role from current database authority;
// no path or bytes from an API caller select the exported database.
func OpenCandidateTransfer(ctx context.Context, database string, uid uint32, d CandidateTransferDescriptor) (*CandidateTransferSource, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, transferFailure(generated.ErrorCodePrerequisiteBlocked)
	}
	p, e := DeriveCandidatePaths(database, d.Binding.PlanID)
	if e != nil {
		return nil, e
	}
	if e = secureRecoveryParent(p.Candidate, uid); e != nil {
		return nil, e
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, e = os.Lstat(p.Candidate + suffix); !os.IsNotExist(e) {
			return nil, transferFailure(generated.ErrorCodeStateConflict)
		}
	}
	open := func(path string, max int64) (*os.File, int64, string, error) {
		fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if e != nil {
			return nil, 0, "", e
		}
		f := os.NewFile(uintptr(fd), path)
		fail := func() (*os.File, int64, string, error) {
			f.Close()
			return nil, 0, "", transferFailure(generated.ErrorCodeIntegrityFailure)
		}
		i, e := f.Stat()
		if e != nil {
			return fail()
		}
		st, ok := i.Sys().(*syscall.Stat_t)
		if !ok || !i.Mode().IsRegular() || i.Mode().Perm() != 0600 || st.Uid != uid || st.Nlink != 1 || i.Size() <= 0 || i.Size() > max {
			return fail()
		}
		h := sha256.New()
		n, e := io.Copy(h, contextTransferReader{ctx: ctx, r: f})
		if e != nil || n != i.Size() {
			return fail()
		}
		after, e := f.Stat()
		if e != nil || after.Size() != i.Size() || !after.ModTime().Equal(i.ModTime()) {
			return fail()
		}
		if _, e = f.Seek(0, io.SeekStart); e != nil {
			return fail()
		}
		return f, n, "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
	}
	c, n, digest, e := open(p.Candidate, MaximumCandidateTransferBytes)
	if e != nil {
		return nil, e
	}
	j, jn, jdigest, e := open(p.TransitionJournal, 32768)
	if e != nil {
		c.Close()
		return nil, e
	}
	out := &CandidateTransferSource{Descriptor: d, Candidate: c, Journal: j}
	out.Descriptor.Schema = generated.SchemaIDControlRecoveryReceiveInput
	out.Descriptor.SchemaVersion = "1.0.0"
	out.Descriptor.CandidateBytes = n
	out.Descriptor.CandidateBytesDigest = digest
	out.Descriptor.JournalBytes = jn
	if jdigest != d.JournalDigest {
		out.Close()
		return nil, transferFailure(generated.ErrorCodeIntegrityFailure)
	}
	if e = ValidateCandidateTransferDescriptor(out.Descriptor); e != nil {
		out.Close()
		return nil, e
	}
	return out, nil
}

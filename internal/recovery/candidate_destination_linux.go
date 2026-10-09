//go:build linux

package recovery

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"syscall"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostreplacement"
	"golang.org/x/sys/unix"
)

func (s LocalCandidateStorage) InspectReplacementDestination(ctx context.Context, database string, paths CandidatePaths, snapshotBytes int64) (hostreplacement.ReplacementDestination, error) {
	var out hostreplacement.ReplacementDestination
	deny := func() (hostreplacement.ReplacementDestination, error) {
		return out, failure.New(generated.ErrorCodePrerequisiteBlocked, "replacement-destination", false)
	}
	if ctx == nil || ctx.Err() != nil || snapshotBytes <= 0 || secureRecoveryParent(paths.Candidate, s.ExpectedUID) != nil || filepath.Dir(database) != filepath.Dir(paths.Candidate) {
		return deny()
	}
	for _, path := range []string{paths.Candidate, paths.PreservedAuthority, paths.TransitionJournal} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return deny()
		}
	}
	// Open the exact protected directory without following a final symlink. The
	// same filesystem owns candidate, current authority and preserved authority.
	fd, err := unix.Open(filepath.Dir(database), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return deny()
	}
	defer unix.Close(fd)
	var directoryStat unix.Stat_t
	if unix.Fstat(fd, &directoryStat) != nil {
		return deny()
	}
	var fs unix.Statfs_t
	if unix.Fstatfs(fd, &fs) != nil || fs.Bsize <= 0 || fs.Bavail > uint64(math.MaxInt64)/uint64(fs.Bsize) {
		return deny()
	}
	available := int64(fs.Bavail) * fs.Bsize
	type preimage struct {
		Name          string
		Device, Inode uint64
		Size          int64
	}
	files := []preimage{}
	var preserved int64
	for _, suffix := range []string{"", "-wal", "-shm"} {
		path := database + suffix
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) && suffix != "" {
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() < 0 {
			return deny()
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != s.ExpectedUID || stat.Nlink != 1 || uint64(stat.Dev) != uint64(directoryStat.Dev) {
			return deny()
		}
		if info.Size() > math.MaxInt64-preserved {
			return deny()
		}
		preserved += info.Size()
		files = append(files, preimage{filepath.Base(path), uint64(stat.Dev), stat.Ino, info.Size()})
	}
	// Capacity here is currently available bytes. Reserving preserved bytes as
	// well is deliberately conservative and never treats occupied bytes as free.
	if preserved > available || snapshotBytes > (available-preserved)/2 {
		return deny()
	}
	out.CapacityBytes = available
	out.PreservedBytes = preserved
	out.SnapshotBytes = snapshotBytes
	out.CandidatePreimageDigest = hostaction.Digest(files)
	out.FilesystemObservationDigest = hostaction.Digest(struct {
		BlockSize         int64
		Available, Blocks uint64
	}{fs.Bsize, fs.Bavail, fs.Blocks})
	return out, nil
}

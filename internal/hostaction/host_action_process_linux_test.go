//go:build linux

package hostaction

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

func init() {
	// A directory O_PATH descriptor still supports openat but rejects fsync.
	// Replace only this test child's already-validated temporary directory FD:
	// Claim/Finish execute their real write+sync syscalls and preserve uncertainty.
	processSyncFault = func(r *Receipts) error {
		fd, err := unix.Open("/proc/self/fd/"+strconv.Itoa(int(r.dir.Fd())), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		return unix.Dup3(fd, int(r.dir.Fd()), unix.O_CLOEXEC)
	}
}

func TestHostActionProcessDirectorySyncFailure(t *testing.T) {
	for _, mode := range []string{"claim-sync-failure", "result-sync-failure"} {
		t.Run(mode, func(t *testing.T) {
			c, b, key := processFixture(t)
			c.Mode = mode
			p := startActionProcess(t, c)
			p.authorize(t, b, c.Policy, key, c.Now, "")
			if err := p.wait(t); err == nil {
				t.Fatal("failed directory sync reported success")
			}
			want := 0
			if mode == "result-sync-failure" {
				want = 1
			}
			processEffects(t, c, want)
			if _, err := os.Stat(filepath.Join(c.Root, ExecutionDigest(b)[7:]+".json")); err != nil {
				t.Fatal("uncertain consumed marker lost", err)
			}
			marker, err := os.ReadFile(filepath.Join(c.Root, ExecutionDigest(b)[7:]+".json"))
			if err != nil || len(marker) == 0 {
				t.Fatal("claim write did not reach directory sync", err)
			}
			if mode == "result-sync-failure" {
				result, err := os.ReadFile(filepath.Join(c.Root, ExecutionDigest(b)[7:]+".result.json"))
				if err != nil || len(result) == 0 {
					t.Fatal("result write did not reach directory sync", err)
				}
			}
			processRetryDenied(t, c, b, key, want)
		})
	}
}

//go:build linux

package debianbaseline

import (
	"bytes"
	"context"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestVolumeHeaderCopyCannotBeWrittenEvenAfterReopen(t *testing.T) {
	raw := bytes.Repeat([]byte{7}, 4096)
	f, e := sealedVolumeHeader(raw)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if _, e = f.WriteAt([]byte{8}, 0); e == nil {
		t.Fatal("sealed header writable")
	}
	if e = f.Truncate(0); e == nil {
		t.Fatal("sealed header truncatable")
	}
	again, e := os.OpenFile("/proc/self/fd/"+strconv.Itoa(int(f.Fd())), os.O_RDWR, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer again.Close()
	if _, e = again.WriteAt([]byte{8}, 0); e == nil {
		t.Fatal("reopened header writable")
	}
	got, e := io.ReadAll(f)
	if e != nil || !bytes.Equal(got, raw) {
		t.Fatal("header changed")
	}
}

// Execute a real ELF through the production sealed-executable launcher while
// replacing its original pathname before spawn. Only a synthetic key is used.
func TestVolumeVerifiedExecutableSurvivesPathReplacement(t *testing.T) {
	root, in := volumeRecoveryFixture(t)
	executable, e := os.ReadFile("/bin/cat")
	if e != nil {
		t.Fatal(e)
	}
	toolPath := filepath.Join(root, "usr/sbin/cryptsetup")
	if e = os.WriteFile(toolPath, executable, 0700); e != nil {
		t.Fatal(e)
	}
	policy, digest, e := PrepareVolumeRecoveryPolicy(in, hostaction.BytesDigest(executable))
	if e != nil {
		t.Fatal(e)
	}
	in.Binding.RecoveryReferenceDigest = digest
	if e = os.WriteFile(filepath.Join(root, "etc/vsk-labs/volume-recovery/recovery-data/policy.json"), policy, 0600); e != nil {
		t.Fatal(e)
	}
	calls := 0
	_, e = verifyVolumeRecoveryFiles(context.Background(), root, uint32(os.Getuid()), in, func(ctx context.Context, verified []byte, _, key *os.File, _ int64) error {
		calls++
		if e := os.WriteFile(toolPath, []byte("unverified replacement must not execute"), 0700); e != nil {
			return e
		}
		got, e := volumeCommand(ctx, verified, []string{"/proc/self/fd/3"}, []*os.File{key}, 4096)
		if e != nil {
			return e
		}
		if string(got) != "synthetic-key-canary" {
			t.Fatal("wrong process output")
		}
		return nil
	}, time.Now())
	if e != nil || calls != 1 {
		t.Fatal(e, calls)
	}
}

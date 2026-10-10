//go:build linux

package debianbaseline

import (
	"bytes"
	"testing"

	"golang.org/x/sys/unix"
)

func TestNativeSealWitnessMeasuresKernelDenials(t *testing.T) {
	raw := bytes.Repeat([]byte{7}, 4096)
	w, err := observeSealedHeader(raw)
	if err != nil {
		t.Fatal(err)
	}
	if w.WriteErrno != int(unix.EPERM) || w.ResizeErrno != int(unix.EPERM) || w.ReopenWriteErrno != int(unix.EPERM) || w.CopyBeforeDigest == "" || w.CopyBeforeDigest != w.CopyAfterDigest {
		t.Fatalf("invalid native seal witness: %+v", w)
	}
	if !bytes.Equal(raw, bytes.Repeat([]byte{7}, 4096)) {
		t.Fatal("source mutated")
	}
	if _, err := observeSealedHeader([]byte{1}); err == nil {
		t.Fatal("invalid header accepted")
	}
}

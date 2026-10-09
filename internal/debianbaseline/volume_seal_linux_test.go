//go:build linux

package debianbaseline

import (
	"bytes"
	"io"
	"os"
	"strconv"
	"testing"
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

//go:build linux || darwin

package hostaction

import (
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestReceiptClaimSurvivesReopen(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	first, err := OpenReceipts(root, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	if err = first.Claim(digest); err != nil {
		t.Fatal(err)
	}
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := OpenReceipts(root, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err = second.Claim(digest); err == nil {
		t.Fatal("replayed after reopen")
	}
}
func TestConcurrentReceiptHasOneWinner(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	var successes atomic.Int32
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := OpenReceipts(root, uint32(os.Geteuid()))
			if err != nil {
				t.Error(err)
				return
			}
			defer r.Close()
			if r.Claim("sha256:"+strings.Repeat("b", 64)) == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("winners=%d", successes.Load())
	}
}
func TestReceiptRejectsUnsafeDirectory(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	link := root + "/link"
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if r, err := OpenReceipts(link, uint32(os.Geteuid())); err == nil {
		r.Close()
		t.Fatal("accepted symlink")
	}
	if err := os.Chmod(root, 0777); err != nil {
		t.Fatal(err)
	}
	if r, err := OpenReceipts(root, uint32(os.Geteuid())); err == nil {
		r.Close()
		t.Fatal("accepted unsafe modes")
	}
}

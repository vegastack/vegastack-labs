//go:build linux || darwin

package recovery

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

func TestFileReceiptStoreConsumesOnceAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	first := fileReceiptStore{directory: dir, expectedUID: uint32(os.Geteuid())}
	const tries = 8
	var wg sync.WaitGroup
	results := make(chan error, tries)
	for i := 0; i < tries; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- first.Consume(context.Background(), "receipt-1", "challenge-1") }()
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("one-use successes=%d", successes)
	}
	restarted := fileReceiptStore{directory: dir, expectedUID: uint32(os.Geteuid())}
	if err := restarted.Consume(context.Background(), "receipt-1", "challenge-1"); err == nil {
		t.Fatal("receipt replayed after restart")
	}
	if err := restarted.Consume(context.Background(), "receipt-1", "challenge-2"); err == nil {
		t.Fatal("receipt reused with a new challenge")
	}
	if err := restarted.Consume(context.Background(), "receipt-2", "challenge-1"); err == nil {
		t.Fatal("challenge reused with a new receipt")
	}
	// The rejected cross-pair conservatively burns receipt-2; only two fresh
	// identities can form another attempt.
	if err := restarted.Consume(context.Background(), "receipt-3", "challenge-2"); err != nil {
		t.Fatal(err)
	}
}

func TestFileReceiptStoreSyncsFirstClaimBeforeSecondClaimFails(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	owner := uint32(os.Geteuid())
	first := fileReceiptStore{directory: dir, expectedUID: owner}
	if err := first.Consume(context.Background(), "receipt-old", "challenge-used"); err != nil {
		t.Fatal(err)
	}
	directorySyncs := 0
	restarted := fileReceiptStore{directory: dir, expectedUID: owner, syncDirectory: func(fd int) error {
		directorySyncs++
		return unix.Fsync(fd)
	}}
	if err := restarted.Consume(context.Background(), "receipt-partial", "challenge-used"); err == nil {
		t.Fatal("reused challenge accepted")
	}
	if directorySyncs != 1 {
		t.Fatalf("first marker was not durable before second claim failed: directory syncs=%d", directorySyncs)
	}
	if err := (fileReceiptStore{directory: dir, expectedUID: owner}).Consume(context.Background(), "receipt-partial", "challenge-fresh"); err == nil {
		t.Fatal("partial receipt claim was reused after store reconstruction")
	}
}

func TestFileReceiptStoreRejectsWeakDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	store := fileReceiptStore{directory: dir, expectedUID: uint32(os.Geteuid())}
	if err := store.Consume(context.Background(), "receipt-1", "challenge-1"); err == nil {
		t.Fatal("weak directory accepted")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	store.directory = link
	if err := store.Consume(context.Background(), "receipt-1", "challenge-1"); err == nil {
		t.Fatal("symlink directory accepted")
	}
}

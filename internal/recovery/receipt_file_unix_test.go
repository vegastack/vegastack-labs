//go:build linux || darwin

package recovery

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
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
	if err := restarted.Consume(context.Background(), "receipt-2", "challenge-1"); err != nil {
		t.Fatal(err)
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

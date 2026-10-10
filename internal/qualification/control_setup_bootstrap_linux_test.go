//go:build linux

package qualification

import (
	"context"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBootstrapProfileMarkerIsOnlyProtectedBoundedScheduling(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires disposable root fixture")
	}
	root := t.TempDir()
	path := filepath.Join(root, "ready")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if awaitFixtureBootstrapProfileAt(ctx, path) == nil {
		t.Fatal("missing marker admitted")
	}
	if _, e := os.Lstat(path); !os.IsNotExist(e) {
		t.Fatal("wait created a marker")
	}
	if os.WriteFile(path, nil, 0600) != nil {
		t.Fatal("fixture")
	}
	if awaitFixtureBootstrapProfileAt(context.Background(), path) != nil {
		t.Fatal("protected marker rejected")
	}
	for _, variant := range []string{"payload", "loose", "foreign", "symlink", "hardlink", "fifo", "cancelled"} {
		t.Run(variant, func(t *testing.T) {
			usePath := path
			c := context.Background()
			switch variant {
			case "payload":
				os.WriteFile(path, []byte("authority"), 0600)
				defer os.WriteFile(path, nil, 0600)
			case "loose":
				os.Chmod(path, 0644)
				defer os.Chmod(path, 0600)
			case "foreign":
				os.Chown(path, 65534, 65534)
				defer os.Chown(path, 0, 0)
			case "symlink":
				usePath = path + ".link"
				if os.Symlink(path, usePath) != nil {
					t.Fatal("fixture")
				}
				defer os.Remove(usePath)
			case "hardlink":
				usePath = path + ".hard"
				if os.Link(path, usePath) != nil {
					t.Fatal("fixture")
				}
				defer os.Remove(usePath)
			case "fifo":
				usePath = path + ".fifo"
				if unix.Mkfifo(usePath, 0600) != nil {
					t.Fatal("fixture")
				}
				defer os.Remove(usePath)
			case "cancelled":
				var stop context.CancelFunc
				c, stop = context.WithCancel(c)
				stop()
			}
			if awaitFixtureBootstrapProfileAt(c, usePath) == nil {
				t.Fatal("marker protection widened")
			}
		})
	}
}

//go:build linux

package backup

import (
	"context"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
)

// TestPinnedResticEndToEnd is the Linux acceptance lane. CI sets the path to
// the official SHA-pinned 0.19.1 binary; local runs skip if it is unavailable.
// It exercises the real child, sealed password FD, Unix REST v2 boundary and
// two sequential encrypted points against an isolated temporary repository.
func TestPinnedResticEndToEnd(t *testing.T) {
	binary := os.Getenv("VSK_RESTIC_0191_BINARY")
	if binary == "" {
		t.Skip("official pinned restic 0.19.1 binary not provided")
	}
	fixture := t.TempDir()
	root := filepath.Join(fixture, "repository")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	lease := WriterLease{LeaseID: "lease-real", PolicyID: "policy-real", PointID: "point-real", PlanID: "plan-real",
		PlanDigest: "sha256:" + strings.Repeat("a", 64), RunID: "run-real", StepID: "step-real",
		RepositoryID: "repo-real", RepositoryClass: "standard", TargetID: "target-real",
		MaximumExpiresAt: time.Now().Add(10 * time.Minute)}
	server, err := NewRESTServer(root, uint32(os.Geteuid()), lease, allowingLeaseVerifier{}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(fixture, "rest.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	defer listener.Close()
	go func() { _ = server.Serve(ctx, listener) }()
	password, err := credentialref.NewValue([]byte("isolated-restic-0191-fixture-password"))
	if err != nil {
		t.Fatal(err)
	}
	defer password.Close()
	runner := NewResticRunner()
	request := ResticRequest{BinaryPath: binary, Architecture: runtime.GOARCH,
		RepositoryURL: "http+unix://" + url.PathEscape(socket) + ":/repo-real/",
		RepositoryID:  "repo-real", RepositoryClass: "standard", RepositoryRoot: root,
		PolicyDigest: "sha256:" + strings.Repeat("b", 64), Lease: lease}
	request.Mode = "init"
	if _, err := runner.Run(ctx, request, password); err != nil {
		observation := runner.Observation()
		t.Fatalf("real restic init: %v; child stdout=%q stderr=%q", err,
			strings.ReplaceAll(observation.Stdout, string(password.Bytes()), "[redacted]"),
			strings.ReplaceAll(observation.Stderr, string(password.Bytes()), "[redacted]"))
	}
	snapshot := filepath.Join(fixture, "snapshot.sqlite")
	request.Mode = "backup"
	request.SnapshotPath = snapshot
	for point := 1; point <= 2; point++ {
		if err := os.WriteFile(snapshot, []byte(strings.Repeat("captured-sqlite-page", 4096)+string(rune('0'+point))), 0o600); err != nil {
			t.Fatal(err)
		}
		result, err := runner.Run(ctx, request, password)
		if err != nil {
			t.Fatalf("real restic backup %d: %v", point, err)
		}
		if result.RepositoryFormat != 2 || result.SnapshotID == "" || result.SnapshotCount != 1 {
			t.Fatalf("backup %d result = %#v", point, result)
		}
	}
	entries, err := os.ReadDir(filepath.Join(root, "snapshots"))
	if err != nil || len(entries) != 2 {
		t.Fatalf("sequential snapshots: %d entries, %v", len(entries), err)
	}
}

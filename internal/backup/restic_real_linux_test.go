//go:build linux

package backup

import (
	"context"
	"net"
	"os"
	"os/exec"
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
		RepositoryURL: "http+unix://" + socket + ":/repo-real/",
		RepositoryID:  "repo-real", RepositoryClass: "standard", RepositoryRoot: root,
		PolicyDigest: "sha256:" + strings.Repeat("b", 64), Lease: lease}
	request.Mode = "init"
	if _, err := runner.Run(ctx, request, password); err != nil {
		observation := runner.Observation()
		t.Fatalf("real restic init: %v; child stdout=%q stderr=%q", err,
			strings.ReplaceAll(observation.Stdout, string(password.Bytes()), "[redacted]"),
			strings.ReplaceAll(observation.Stderr, string(password.Bytes()), "[redacted]"))
	}
	request.Mode = "config"
	if result, err := runner.Run(ctx, request, password); err != nil || result.RepositoryFormat != 2 {
		observation := runner.Observation()
		t.Fatalf("real restic config preflight: format=%d err=%v stderr=%q", result.RepositoryFormat, err,
			strings.ReplaceAll(observation.Stderr, string(password.Bytes()), "[redacted]"))
	}
	snapshot := filepath.Join(fixture, "snapshot.sqlite")
	request.Mode = "backup"
	request.SnapshotPath = snapshot
	var lastSnapshotID string
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
		lastSnapshotID = result.SnapshotID
	}
	// The independent read role must see the exact snapshot IDs and perform a
	// full payload read before an isolated exact-ID restore. This uses the real
	// pinned child and REST locks; the earlier backup result alone is not proof.
	readLease := ReadLease{LeaseID: "read-real", PointID: "point-real", RepositoryID: "repo-real", MaximumExpiresAt: time.Now().Add(10 * time.Minute)}
	readServer, err := NewVerifierRESTServer(root, uint32(os.Geteuid()), readLease, allowingReadLeaseVerifier{}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	readSocket := filepath.Join(fixture, "read.sock")
	readListener, err := net.Listen("unix", readSocket)
	if err != nil {
		t.Fatal(err)
	}
	defer readListener.Close()
	go func() { _ = readServer.Serve(ctx, readListener) }()
	readRequest := request
	readRequest.RepositoryURL = "http+unix://" + readSocket + ":/repo-real/"
	readRequest.Mode = "snapshots"
	readRequest.OutputLimit = 4 << 20
	snapshots, err := runner.Run(ctx, readRequest, password)
	if err != nil || len(snapshots.SnapshotIDs) != 2 {
		t.Fatalf("exact snapshots: %v %#v", err, snapshots)
	}
	readRequest.Mode = "check-full"
	if _, err := runner.Run(ctx, readRequest, password); err != nil {
		t.Fatalf("full payload read: %v", err)
	}
	target, err := os.MkdirTemp(filepath.Dir(root), ".vsk-backup-verify-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(target)
	readRequest.Mode = "restore"
	readRequest.SnapshotID = lastSnapshotID
	readRequest.RestoreTarget = target
	if _, err := runner.Run(ctx, readRequest, password); err != nil {
		t.Fatalf("isolated exact restore: %v", err)
	}
	if _, err := os.Stat(filepath.Join(target, strings.TrimPrefix(snapshot, "/"))); err != nil {
		t.Fatalf("restored snapshot missing: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(root, "snapshots"))
	if err != nil || len(entries) != 2 {
		t.Fatalf("sequential snapshots: %d entries, %v", len(entries), err)
	}
}

func TestPinnedResticRejectsAuthenticatedV1Repository(t *testing.T) {
	binary := os.Getenv("VSK_RESTIC_0191_BINARY")
	if binary == "" {
		t.Skip("official pinned restic 0.19.1 binary not provided")
	}
	fixture := t.TempDir()
	root := filepath.Join(fixture, "repository-v1")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	lease := WriterLease{LeaseID: "lease-v1", PolicyID: "policy-v1", PointID: "point-v1", PlanID: "plan-v1",
		PlanDigest: "sha256:" + strings.Repeat("a", 64), RunID: "run-v1", StepID: "step-v1",
		RepositoryID: "repo-v1", RepositoryClass: "standard", TargetID: "target-v1",
		MaximumExpiresAt: time.Now().Add(10 * time.Minute)}
	server, err := NewRESTServer(root, uint32(os.Geteuid()), lease, allowingLeaseVerifier{}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(fixture, "rest-v1.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	defer listener.Close()
	go func() { _ = server.Serve(ctx, listener) }()
	password, err := credentialref.NewValue([]byte("isolated-restic-v1-fixture-password"))
	if err != nil {
		t.Fatal(err)
	}
	defer password.Close()
	request := ResticRequest{BinaryPath: binary, Architecture: runtime.GOARCH,
		RepositoryURL: "http+unix://" + socket + ":/repo-v1/", RepositoryID: "repo-v1"}
	// The production runner only initializes v2. Build this valid v1 negative
	// fixture with the same verified inode and sealed password FD.
	runner := &resticRunner{clock: time.Now}
	binaryFile, err := runner.verifyBinary(request)
	if err != nil {
		t.Fatalf("verify official restic binary: %v", err)
	}
	defer binaryFile.Close()
	passwordFile, err := sealedPasswordFile(password.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	defer passwordFile.Close()
	command := exec.CommandContext(ctx, binary, "-r", "rest:"+request.RepositoryURL,
		"--no-cache", "--password-file", passwordFilePath, "init", "--repository-version", "1")
	command.Path = "/proc/self/fd/4"
	command.ExtraFiles = []*os.File{passwordFile, binaryFile}
	command.Env = []string{}
	if err := command.Run(); err != nil {
		t.Fatalf("initialize authenticated v1 fixture: %v", err)
	}
	request.Mode = "config"
	if _, err := runner.Run(ctx, request, password); err == nil || !strings.Contains(err.Error(), "backup-restic-config") {
		t.Fatalf("valid v1 repository was not rejected at authenticated format preflight: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(root, "snapshots"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("v1 preflight created a snapshot: entries=%d err=%v", len(entries), err)
	}
}

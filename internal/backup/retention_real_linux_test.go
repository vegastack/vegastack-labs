//go:build linux

package backup

import (
	"bytes"
	"context"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
)

// This is a disposable restic 0.19.1 experiment, not a live retirement
// acceptance. It proves that a shared survivor can still be restored after
// exact-ID forget/prune while old keys stay in quarantine for crash recovery.
func TestPinnedResticRetentionQuarantinesSharedPackUntilSuccessorProof(t *testing.T) {
	binary := os.Getenv("VSK_RESTIC_0191_BINARY")
	if binary == "" {
		t.Skip("official pinned restic 0.19.1 binary not provided")
	}
	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	root, quarantine := filepath.Join(base, "repository"), filepath.Join(base, "quarantine")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	lease := WriterLease{LeaseID: "writer-retirement-fixture", PolicyID: "policy-retirement-fixture", PointID: "point-retirement-fixture",
		PlanID: "plan-retirement-fixture", PlanDigest: "sha256:" + strings.Repeat("a", 64), RunID: "run-retirement-fixture",
		StepID: "step-retirement-fixture", RepositoryID: "repo-retirement-fixture", RepositoryClass: "standard",
		TargetID: "target-retirement-fixture", MaximumExpiresAt: time.Now().Add(5 * time.Minute)}
	writer, err := NewRESTServer(root, uint32(os.Geteuid()), lease, allowingLeaseVerifier{}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	writerSocket := filepath.Join(base, "writer.sock")
	writerListener, err := net.Listen("unix", writerSocket)
	if err != nil {
		t.Fatal(err)
	}
	defer writerListener.Close()
	go func() { _ = writer.Serve(ctx, writerListener) }()
	password, err := credentialref.NewValue([]byte("disposable-retirement-only-password"))
	if err != nil {
		t.Fatal(err)
	}
	defer password.Close()
	runner := NewResticRunner()
	request := ResticRequest{BinaryPath: binary, Architecture: runtime.GOARCH,
		RepositoryURL: "http+unix://" + writerSocket + ":/repo-retirement-fixture/",
		RepositoryID:  lease.RepositoryID, RepositoryClass: "standard", RepositoryRoot: root,
		PolicyDigest: "sha256:" + strings.Repeat("b", 64), Lease: lease}
	request.Mode = "init"
	if _, err := runner.Run(ctx, request, password); err != nil {
		t.Fatalf("init: %v", err)
	}
	data := filepath.Join(base, "data")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	shared := make([]byte, 1<<20)
	changing := make([]byte, 1<<20)
	if _, err := rand.Read(shared); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(changing); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "shared"), shared, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "changing"), changing, 0o600); err != nil {
		t.Fatal(err)
	}
	// One file spans multiple content-defined chunks, placing retained and
	// replaced chunks in the same old data pack for the prune experiment.
	mixed := make([]byte, 8<<20)
	if _, err := rand.Read(mixed); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "mixed"), mixed, 0o600); err != nil {
		t.Fatal(err)
	}
	request.Mode, request.SnapshotPath = "backup", data
	first, err := runner.Run(ctx, request, password)
	if err != nil {
		t.Fatalf("first backup: %v", err)
	}
	if _, err := rand.Read(changing); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "changing"), changing, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(mixed[6<<20 : 7<<20]); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "mixed"), mixed, 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := runner.Run(ctx, request, password)
	if err != nil {
		t.Fatalf("second backup: %v", err)
	}
	journal := &retentionJournalFixture{}
	retentionLease := RetentionLease{LeaseID: "retention-fixture", RepositoryID: lease.RepositoryID, RecoveryEpoch: 0,
		MaximumExpiresAt: time.Now().Add(5 * time.Minute), MaxMutations: 1000, MaxMutationBytes: 512 << 20,
		PlannedSnapshotIDs: []string{first.SnapshotID}}
	retention, err := NewRetentionRESTServer(root, quarantine, uint32(os.Geteuid()), retentionLease, allowingRetentionLeaseVerifier{}, journal, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	retentionSocket := filepath.Join(base, "retention.sock")
	retentionListener, err := net.Listen("unix", retentionSocket)
	if err != nil {
		t.Fatal(err)
	}
	defer retentionListener.Close()
	go func() { _ = retention.Serve(ctx, retentionListener) }()
	retentionURL := "http+unix://" + retentionSocket + ":/repo-retirement-fixture/"
	for _, mode := range []string{"forget-dry-run", "forget", "prune"} {
		child := RetentionResticRequest{BinaryPath: binary, RepositoryURL: retentionURL, Mode: mode,
			SnapshotIDs: []string{first.SnapshotID}, MaxRepackBytes: 64 << 20}
		if mode == "prune" {
			child.SnapshotIDs = nil
		}
		if _, err := RunRetentionRestic(ctx, child, password); err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
	}
	request.RepositoryURL = retentionURL
	request.Mode = "snapshots"
	snapshots, err := runner.Run(ctx, request, password)
	if err != nil || len(snapshots.SnapshotIDs) != 1 || snapshots.SnapshotIDs[0] != second.SnapshotID {
		t.Fatalf("post-prune snapshots=%#v err=%v", snapshots, err)
	}
	request.Mode = "check-full"
	if _, err := runner.Run(ctx, request, password); err != nil {
		t.Fatalf("post-prune full read: %v", err)
	}
	target := filepath.Join(base, ".vsk-backup-verify-retirement")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	request.Mode, request.SnapshotID, request.RestoreTarget = "restore", second.SnapshotID, target
	if _, err := runner.Run(ctx, request, password); err != nil {
		t.Fatalf("survivor restore: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(target, strings.TrimPrefix(data, "/"), "shared"))
	if err != nil || !bytes.Equal(got, shared) {
		t.Fatalf("shared survivor content lost: %v", err)
	}
	if _, err := os.Stat(filepath.Join(quarantine, "snapshots", first.SnapshotID)); err != nil {
		t.Fatalf("retired snapshot inode not held for uncertain crash: %v", err)
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if len(journal.attempts) < 3 || len(journal.outcomes) != len(journal.attempts) {
		t.Fatalf("incomplete mutation journal: attempts=%d outcomes=%d", len(journal.attempts), len(journal.outcomes))
	}
	var dataPut, dataDelete bool
	for index, attempt := range journal.attempts {
		if attempt.ObjectType != "data" {
			continue
		}
		switch attempt.MutationKind {
		case "put":
			dataPut = true
			if _, err := os.Stat(filepath.Join(root, "data", attempt.ObjectName)); err != nil {
				t.Fatalf("new survivor pack absent after repack: %v", err)
			}
		case "delete":
			dataDelete = true
			if _, err := os.Stat(filepath.Join(quarantine, "data", attempt.ObjectName)); err != nil {
				t.Fatalf("old shared pack inode not quarantined: %v", err)
			}
		}
		if attempt.MutationID == "" || attempt.Sequence != int64(index+1) || journal.outcomes[index].MutationID != attempt.MutationID ||
			journal.outcomes[index].ObjectType != attempt.ObjectType || journal.outcomes[index].ObjectName != attempt.ObjectName {
			t.Fatalf("journal outcome %d does not bind exact object", index)
		}
	}
	if !dataPut || !dataDelete {
		t.Fatalf("fixture did not exercise shared-pack repack: dataPut=%t dataDelete=%t", dataPut, dataDelete)
	}
}

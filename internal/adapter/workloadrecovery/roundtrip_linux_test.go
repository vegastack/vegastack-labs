//go:build linux

package workloadrecovery

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/backup"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

// The SSH peers expose real protocol boundaries, while the official pinned
// restic child performs actual encrypted backup, full reads and isolated restore.
func TestWorkloadRecoveryPinnedResticRoundTrip(t *testing.T) {
	binary := os.Getenv("VSK_RESTIC_0191_BINARY")
	if binary == "" {
		t.Skip("official pinned restic 0.19.1 binary not provided")
	}
	c, q, lease, source, target := recoveryFixture(t)
	c.Profile.ResticBinaryPath = binary
	c.Runner = backup.NewResticRunner()
	out, e := Execute(context.Background(), q, generated.ServiceRecoveryRecord{}, lease, c)
	if e != nil || out.Status != "succeeded" || !out.SourceResumed {
		ob := c.Runner.Observation()
		t.Fatalf("encrypted cold backup: %+v %v child stdout=%q stderr=%q", out, e, strings.ReplaceAll(ob.Stdout, string(c.RepositoryKey.Bytes()), "[redacted]"), strings.ReplaceAll(ob.Stderr, string(c.RepositoryKey.Bytes()), "[redacted]"))
	}
	if out.ManifestDigest == "" || out.SnapshotID == "" {
		t.Fatal("missing actual backup proof")
	}
	previous := generated.ServiceRecoveryRecord{Request: q, Status: out.Status, BackupPointID: out.BackupPointID, SnapshotID: out.SnapshotID, ManifestDigest: out.ManifestDigest, ContentDigest: out.ContentDigest, RuntimeDigest: out.RuntimeDigest, SourceResumed: out.SourceResumed}
	q.Action = "isolated-restore"
	q.BackupPointID = out.BackupPointID
	q.ExpectedRecoveryRevision = 1
	q.IdempotencyKey = "restore-a"
	lease.PointID = out.BackupPointID
	restored, e := Execute(context.Background(), q, previous, lease, c)
	if e != nil || restored.Status != "succeeded" || !restored.IsolatedRestoreVerified || restored.ContentDigest != out.ContentDigest {
		t.Fatalf("isolated restore: %+v %v", restored, e)
	}
	if !source.running || !target.running || target.copies != 1 {
		t.Fatalf("source/target state source=%v target=%v copies=%d", source.running, target.running, target.copies)
	}
	// A populated isolated target cannot be overwritten, even with another plan.
	_, e = Execute(context.Background(), q, previous, lease, c)
	if e == nil {
		t.Fatal("populated running target accepted")
	}
}

//go:build linux

package api

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/recovery"
	"github.com/vegastack/vegastack-labs/internal/store"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Capture through the actual server-owned online backup API before freeze.
// Only external source custody/audit qualification is supplied by this fixture.
func replacementTransferSnapshot(t *testing.T, ctx context.Context, authority *store.Store, databasePath string, source generated.RestoreSourceBinding, audit recovery.AuditContinuity) recovery.VerifiedSource {
	t.Helper()
	online, e := store.NewOnlineSnapshotSource(authority)
	if e != nil {
		t.Fatal(e)
	}
	expected, e := online.CurrentExpectation(ctx)
	if e != nil {
		t.Fatal(e)
	}
	destination := filepath.Join(t.TempDir(), "snapshot.db")
	if destination == databasePath {
		t.Fatal("snapshot aliases source")
	}
	if e = os.Chmod(filepath.Dir(destination), 0700); e != nil {
		t.Fatal(e)
	}
	captured, e := online.OnlineSnapshot(ctx, store.OnlineSnapshotRequest{Destination: destination, Expected: expected, BusyBudget: time.Second})
	if e != nil {
		t.Fatal(e)
	}
	digest := "sha256:" + hex.EncodeToString(captured.DatabaseSHA256[:])
	reader := replacementTransferSnapshotReader{path: destination, point: source.PointID, digest: digest, size: captured.Bytes, audit: audit}
	return recovery.VerifiedSource{Binding: source, Snapshot: reader, DatabaseDigest: digest, Audit: audit}
}

type replacementTransferSnapshotReader struct {
	path, point, digest string
	size                int64
	audit               recovery.AuditContinuity
}

func (r replacementTransferSnapshotReader) check(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	f, e := os.Open(r.path)
	if e != nil {
		return e
	}
	defer f.Close()
	h := sha256.New()
	n, e := io.Copy(h, f)
	if e != nil {
		return e
	}
	if n != r.size || "sha256:"+hex.EncodeToString(h.Sum(nil)) != r.digest {
		return os.ErrInvalid
	}
	return nil
}
func (r replacementTransferSnapshotReader) InspectAudit(ctx context.Context) (recovery.AuditContinuity, error) {
	return r.audit, r.check(ctx)
}
func (r replacementTransferSnapshotReader) InspectSnapshotBytes(ctx context.Context) (int64, error) {
	return r.size, r.check(ctx)
}
func (r replacementTransferSnapshotReader) InspectHostAliasWatermark(ctx context.Context) (int64, error) {
	if e := r.check(ctx); e != nil {
		return 0, e
	}
	u := url.URL{Scheme: "file", Path: r.path}
	q := u.Query()
	q.Set("mode", "ro")
	q.Set("immutable", "1")
	u.RawQuery = q.Encode()
	db, e := sql.Open("sqlite3", u.String())
	if e != nil {
		return 0, e
	}
	defer db.Close()
	var n int64
	e = db.QueryRowContext(ctx, `SELECT COALESCE(MAX(event_ordinal),0) FROM host_alias_history`).Scan(&n)
	return n, e
}
func (r replacementTransferSnapshotReader) Restore(ctx context.Context, target recovery.CandidateTarget, b generated.RestoreBinding) (recovery.SnapshotReceipt, error) {
	if e := r.check(ctx); e != nil {
		return recovery.SnapshotReceipt{}, e
	}
	destination, ok := recovery.CandidateTargetPath(target)
	if !ok || b.PointID != r.point {
		return recovery.SnapshotReceipt{}, os.ErrInvalid
	}
	src, e := os.Open(r.path)
	if e != nil {
		return recovery.SnapshotReceipt{}, e
	}
	defer src.Close()
	dst, e := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return recovery.SnapshotReceipt{}, e
	}
	defer dst.Close()
	n, e := io.Copy(dst, src)
	if e != nil {
		return recovery.SnapshotReceipt{}, e
	}
	if e = dst.Sync(); e != nil {
		return recovery.SnapshotReceipt{}, e
	}
	if n != r.size {
		return recovery.SnapshotReceipt{}, os.ErrInvalid
	}
	return recovery.SnapshotReceipt{PointID: r.point, SnapshotID: "native-transfer-snapshot", ContentDigest: r.digest, Bytes: n}, nil
}

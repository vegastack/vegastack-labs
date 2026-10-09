//go:build linux

package recovery

import (
	"context"
	"math"
	"os"
	"path/filepath"
	"testing"
)

func TestReplacementDestinationMeasuresActualCapacityAndPreservedFiles(t *testing.T) {
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	database := filepath.Join(dir, "control.db")
	if e := os.WriteFile(database, []byte("preserved-authority"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(database+"-wal", []byte("current-wal"), 0600); e != nil {
		t.Fatal(e)
	}
	paths, e := DeriveCandidatePaths(database, "plan-a")
	if e != nil {
		t.Fatal(e)
	}
	storage := LocalCandidateStorage{ExpectedUID: uint32(os.Geteuid())}
	observed, e := storage.InspectReplacementDestination(context.Background(), database, paths, 4096)
	if e != nil {
		t.Fatal(e)
	}
	if observed.CapacityBytes <= 0 || observed.SnapshotBytes != 4096 || observed.PreservedBytes != int64(len("preserved-authoritycurrent-wal")) || observed.CandidatePreimageDigest == "" || observed.FilesystemObservationDigest == "" {
		t.Fatalf("bad measurement: %+v", observed)
	}
	// Actual available capacity must reject an impossible snapshot without
	// creating a candidate or touching the preserved authority.
	if _, e = storage.InspectReplacementDestination(context.Background(), database, paths, math.MaxInt64); e == nil {
		t.Fatal("insufficient measured capacity accepted")
	}
	if _, e = os.Lstat(paths.Candidate); !os.IsNotExist(e) {
		t.Fatal("preflight wrote candidate")
	}
	before := observed.CandidatePreimageDigest
	if e = os.WriteFile(database+"-wal", []byte("changed-current-wal"), 0600); e != nil {
		t.Fatal(e)
	}
	changed, e := storage.InspectReplacementDestination(context.Background(), database, paths, 4096)
	if e != nil || changed.CandidatePreimageDigest == before {
		t.Fatalf("changed preimage not observed: %v", e)
	}
	for _, path := range []string{paths.Candidate, paths.PreservedAuthority, paths.TransitionJournal} {
		if e = os.WriteFile(path, []byte("unknown"), 0600); e != nil {
			t.Fatal(e)
		}
		if _, e = storage.InspectReplacementDestination(context.Background(), database, paths, 4096); e == nil {
			t.Fatalf("existing %s accepted", path)
		}
		if e = os.Remove(path); e != nil {
			t.Fatal(e)
		}
	}
	if e = os.Remove(database + "-wal"); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink(database, database+"-wal"); e != nil {
		t.Fatal(e)
	}
	if _, e = storage.InspectReplacementDestination(context.Background(), database, paths, 4096); e == nil {
		t.Fatal("symlink preimage accepted")
	}
}

// Interface assertion ensures the production storage actually implements the
// capability consumed before any replacement candidate staging operation.
var _ replacementDestinationInspector = LocalCandidateStorage{}

func (reader fileSnapshotReader) InspectSnapshotBytes(ctx context.Context) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	info, err := os.Lstat(reader.path)
	if err != nil {
		return 0, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 {
		return 0, os.ErrInvalid
	}
	return info.Size(), nil
}

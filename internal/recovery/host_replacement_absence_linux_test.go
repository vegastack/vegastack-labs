//go:build linux

package recovery

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type aliasWatermarkSnapshot struct {
	snapshotStub
	watermark int64
	err       error
	inspected *bool
}

func (s aliasWatermarkSnapshot) InspectHostAliasWatermark(context.Context) (int64, error) {
	*s.inspected = true
	return s.watermark, s.err
}

func TestReplacementEmptyAuthorityStillInspectsVerifiedSourceHistory(t *testing.T) {
	for _, mode := range []string{"empty", "source-owned", "source-unavailable", "unsupported"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "control.db")
			authority, err := store.Open(ctx, store.Config{DatabasePath: path, Mode: store.InitializeNew, BusyTimeout: time.Second, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "test", BuildVersion: "test"})
			if err != nil {
				t.Fatal(err)
			}
			defer authority.Close()
			checked := false
			reader := aliasWatermarkSnapshot{inspected: &checked}
			switch mode {
			case "source-owned":
				reader.watermark = 7
			case "source-unavailable":
				reader.err = ErrWitnessUnavailable
			}
			source := VerifiedSource{Binding: generated.RestoreSourceBinding{PointID: "point-a"}, DatabaseDigest: testCandidateDigest("a"), Snapshot: reader}
			if mode == "unsupported" {
				source.Snapshot = snapshotStub{}
			}
			guard := StoreReplacementContinuityGuard{Authority: authority, Replacements: store.NewHostReplacementRepository(authority)}
			ref, err := guard.PrepareReplacementContinuity(ctx, generated.RestoreRequest{}, source)
			if (err == nil) != (mode == "empty") || ref != nil {
				t.Fatalf("mode %s ref=%v err=%v", mode, ref, err)
			}
			if mode != "unsupported" && !checked {
				t.Fatal("zero local history bypassed verified source inspection")
			}
		})
	}
}

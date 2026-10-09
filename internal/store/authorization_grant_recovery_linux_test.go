//go:build linux

package store

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"os"
	"path/filepath"
	"testing"
)

func TestGrantRecoveryRequiresRestorableCurrentPrivatePreimage(t *testing.T) {
	for _, variant := range []string{"restorable", "stale-state", "stale-epoch", "corrupt-preimage", "symlink-preimage", "occupied-restore"} {
		t.Run(variant, func(t *testing.T) {
			s := openEffectiveAuthorizationStore(t)
			defer s.Close()
			ctx := context.Background()
			rev, err := NewPlanRepository(s).CurrentRevision(ctx)
			if err != nil {
				t.Fatal(err)
			}
			p := generated.Plan{PlanDigest: testDigest, Binding: generated.PlanBinding{StateRevision: rev.StateRevision, RecoveryEpoch: rev.RecoveryEpoch}}
			in := GrantBatchApply{RunID: "run-grant-recovery", PlanDigest: testDigest}
			name := string(digestParts("authorization-before", in.RunID, in.PlanDigest))[7:39]
			before := filepath.Join(filepath.Dir(s.config.DatabasePath), "authorization-before-"+name+".db")
			probe := filepath.Join(filepath.Dir(s.config.DatabasePath), "authorization-restore-check-"+name+".db")
			switch variant {
			case "stale-state":
				p.Binding.StateRevision++
			case "stale-epoch":
				p.Binding.RecoveryEpoch++
			case "corrupt-preimage":
				if err = os.WriteFile(before, []byte("not a SQLite recovery point"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink-preimage":
				if err = os.Symlink(s.config.DatabasePath, before); err != nil {
					t.Fatal(err)
				}
			case "occupied-restore":
				if err = os.WriteFile(probe, []byte("preserve this unrelated preimage"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			path, digest, err := NewGrantBatchRepository(s).prepareGrantSnapshot(ctx, p, in)
			if variant == "restorable" {
				if err != nil || path != before || !restoreDigest(digest) {
					t.Fatal(path, digest, err)
				}
				if _, err = os.Stat(before); err != nil {
					t.Fatal("preimage was not retained", err)
				}
				if _, err = os.Stat(probe); !os.IsNotExist(err) {
					t.Fatal("isolated restore probe retained", err)
				}
			} else if Code(err) != generated.ErrorCodeRecoveryRequired {
				t.Fatal("unsafe recovery precheck accepted", variant, err)
			}
			if variant == "occupied-restore" {
				raw, _ := os.ReadFile(probe)
				if string(raw) != "preserve this unrelated preimage" {
					t.Fatal("preexisting probe changed")
				}
			}
		})
	}
}

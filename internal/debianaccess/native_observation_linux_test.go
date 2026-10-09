//go:build linux

package debianaccess

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNativeRollbackRecollectsOwnedBytesWithoutExportingThem(t *testing.T) {
	root, record, p := rollbackFixture(t)
	record.RunID = "run-native"
	ctx := context.Background()
	boot := filepath.Join(root, "proc/sys/kernel/random/boot_id")
	if err := os.MkdirAll(filepath.Dir(boot), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(boot, []byte(record.BootID), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Arm(ctx, root, record); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("after"), 0600); err != nil {
		t.Fatal(err)
	}
	n := &nativeRuntime{root: root, now: func() time.Time { return record.ArmedAt.Add(time.Second) }}
	before, err := n.observeNativeRollback(ctx, record.Digest())
	if err != nil {
		t.Fatal(err)
	}
	if before.CurrentOwnedDigest != before.AppliedOwnedDigest || before.CurrentOwnedDigest == before.BeforeOwnedDigest {
		t.Fatal("actual applied bytes not measured")
	}
	if err := Restore(ctx, root, record.Digest()); err != nil {
		t.Fatal(err)
	}
	after, err := n.observeNativeRollback(ctx, record.Digest())
	if err != nil {
		t.Fatal(err)
	}
	if after.CurrentOwnedDigest != before.BeforeOwnedDigest || after.State != "restored" {
		t.Fatal("actual restored bytes not recollected")
	}
	encoded, _ := json.Marshal(after)
	if strings.Contains(string(encoded), "70-vsk-access.conf") || strings.Contains(string(encoded), `"before"`) {
		t.Fatal("configuration content/path leaked into witness")
	}
	if err := os.WriteFile(p, []byte("outside-change"), 0600); err != nil {
		t.Fatal(err)
	}
	changed, err := n.observeNativeRollback(ctx, record.Digest())
	if err != nil {
		t.Fatal(err)
	}
	if changed.CurrentOwnedDigest == before.BeforeOwnedDigest {
		t.Fatal("changed bytes accepted as prior state")
	}
}
func TestNativeRollbackReadNeverCreatesMissingRecordOrLock(t *testing.T) {
	root := t.TempDir()
	n := &nativeRuntime{root: root, now: time.Now}
	if _, err := n.observeNativeRollback(context.Background(), digestBytes([]byte("missing"))); err == nil {
		t.Fatal("missing rollback observed")
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatal("read-only witness created directories")
	}
}

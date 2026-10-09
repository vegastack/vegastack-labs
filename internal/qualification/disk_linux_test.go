//go:build linux

package qualification

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"os"
	"path/filepath"
	"testing"
)

func TestOfflineResetRefusesRunningGuestWithoutTouchingDisk(t *testing.T) {
	scope := scopeFixture()
	scope.OutputRoot = t.TempDir()
	s, err := validateScope(scope)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(scope.OutputRoot, "subject.qcow2")
	before := []byte("existing fixture data")
	if err = os.WriteFile(path, before, 0600); err != nil {
		t.Fatal(err)
	}
	d := &ownedGuestLifecycle{scope: s, launches: map[string]generated.NativeGuestLaunch{"subject": {QEMUPID: int64(os.Getpid())}}}
	if d.ResetStoppedOwnedDisk(context.Background(), "subject") == nil {
		t.Fatal("running guest reset accepted")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(before) {
		t.Fatal("reset touched running disk")
	}
	if _, err = os.Stat(filepath.Join(scope.OutputRoot, "subject.reset-pending.json")); !os.IsNotExist(err) {
		t.Fatal("reset journal written before process refusal")
	}
}
func TestRestartRefusesInterruptedResetWithoutOverwritingJournal(t *testing.T) {
	scope := scopeFixture()
	scope.OutputRoot = t.TempDir()
	s, err := validateScope(scope)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(scope.OutputRoot, "subject.reset-pending.json")
	before := []byte("interrupted original reset")
	if err = os.WriteFile(path, before, 0600); err != nil {
		t.Fatal(err)
	}
	d := &ownedGuestLifecycle{scope: s, launches: map[string]generated.NativeGuestLaunch{"subject": {QEMUPID: 2147483647}}}
	if d.RestartOwned(context.Background(), "subject") == nil {
		t.Fatal("interrupted reset restarted")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(before) {
		t.Fatal("original unresolved reset overwritten")
	}
}

func TestPreparedImageRejectsHiddenBaseAncestor(t *testing.T) {
	good := []byte(`{"format":"qcow2","virtual-size":12884901888}`)
	if validateQEMUImageInfo(good, true, 12*GiB) != nil {
		t.Fatal("standalone base refused")
	}
	for _, raw := range []string{
		`{"format":"qcow2","virtual-size":12884901888,"backing-filename":"/other.qcow2"}`,
		`{"format":"qcow2","virtual-size":12884901888,"full-backing-filename":"/other.qcow2"}`,
		`{"format":"qcow2","virtual-size":12884901888,"backing-filename-format":"qcow2"}`,
	} {
		if validateQEMUImageInfo([]byte(raw), true, 12*GiB) == nil {
			t.Fatal("hidden base ancestor accepted")
		}
	}
	if validateQEMUImageInfo([]byte(`{"format":"qcow2","virtual-size":12884901888,"backing-filename":"/inputs/base.qcow2","full-backing-filename":"/inputs/base.qcow2","backing-filename-format":"qcow2"}`), false, 12*GiB) != nil {
		t.Fatal("exact one-layer child refused")
	}
}

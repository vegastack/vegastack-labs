package cijobrunner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/cijobguard"
)

func TestJobIdentityContainsOnlyPublicAssignmentAndRefusesReplacement(t *testing.T) {
	root := t.TempDir()
	binding := cijobguard.Binding{RunID: "42", JobID: "99", Attempt: 2, LifecycleID: "private-lifecycle", PlanID: "private-plan", LeaseID: "private-lease", Epoch: 3}
	if err := writeJobIdentity(root, binding); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, jobIdentityFilename))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if json.Unmarshal(raw, &got) != nil || len(got) != 3 || got["runId"] != "42" || got["jobId"] != "99" || got["attempt"] != float64(2) {
		t.Fatal("wrong assignment projection", string(raw))
	}
	if strings.Contains(string(raw), "private") {
		t.Fatal("private admission state exposed")
	}
	info, err := os.Stat(filepath.Join(root, jobIdentityFilename))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("metadata permissions", err)
	}
	if writeJobIdentity(root, binding) == nil {
		t.Fatal("existing assignment overwritten")
	}
	other := filepath.Join(t.TempDir(), "preserve")
	if err = os.WriteFile(other, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	linkRoot := t.TempDir()
	if err = os.Symlink(other, filepath.Join(linkRoot, jobIdentityFilename)); err != nil {
		t.Fatal(err)
	}
	if writeJobIdentity(linkRoot, binding) == nil {
		t.Fatal("assignment symlink followed")
	}
	raw, _ = os.ReadFile(other)
	if string(raw) != "preserve" {
		t.Fatal("unrelated file changed")
	}
}

func TestInvalidJobIdentityWritesNothing(t *testing.T) {
	for _, b := range []cijobguard.Binding{{RunID: "042", JobID: "99", Attempt: 1}, {RunID: "42", JobID: "job-name", Attempt: 1}, {RunID: "42", JobID: "99"}} {
		root := t.TempDir()
		if writeJobIdentity(root, b) == nil {
			t.Fatal("invalid assignment accepted")
		}
		entries, _ := os.ReadDir(root)
		if len(entries) != 0 {
			t.Fatal("invalid assignment left a file")
		}
	}
}

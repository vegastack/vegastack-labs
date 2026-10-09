package linuxrole

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPreparationHasNoEffects(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	p, err := Prepare(fixture())
	if err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatal("preparation mutated filesystem")
	}
	if err = ValidatePreparation(p); err != nil {
		t.Fatal(err)
	}
	for _, file := range p.Files {
		if filepath.IsAbs(file.Path) {
			t.Fatal("unbounded path")
		}
	}
	p.Files[0].Content = "ExecStart=/bin/evil"
	if ValidatePreparation(p) == nil {
		t.Fatal("tampered preparation accepted")
	}
}

func TestInertPreparationNeedsNoBaselineProof(t *testing.T) {
	in := fixture()
	in.BaselineSnapshotDigest = ""
	p, e := Prepare(in)
	if e != nil {
		t.Fatal(e)
	}
	if p.Input.BaselineSnapshotDigest != "" {
		t.Fatal("preparation invented baseline proof")
	}
	if ValidateInput(p.Input) == nil {
		t.Fatal("unsealed preparation executable")
	}
}

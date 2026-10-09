//go:build linux

package recovery

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCandidateTransferPreservesPartialAndRejectsOverwrite(t *testing.T) {
	for _, mode := range []string{"exact", "short", "trailing", "digest", "existing"} {
		t.Run(mode, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "candidate")
			data := []byte("actual candidate bytes")
			input := append([]byte(nil), data...)
			want := digestBytes(data)
			switch mode {
			case "short":
				input = input[:3]
			case "trailing":
				input = append(input, 'x')
			case "digest":
				want = digestBytes([]byte("different"))
			case "existing":
				if e := os.WriteFile(p, []byte("preserve"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			e := transferFile(context.Background(), p, uint32(os.Geteuid()), int64(len(data)), want, bytes.NewReader(input))
			if (e == nil) != (mode == "exact") {
				t.Fatalf("mode %s: %v", mode, e)
			}
			got, re := os.ReadFile(p)
			if re != nil {
				t.Fatal(re)
			}
			if mode == "existing" && !bytes.Equal(got, []byte("preserve")) {
				t.Fatal("existing overwritten")
			}
			if mode == "short" && !bytes.Equal(got, input) {
				t.Fatal("partial bytes not retained")
			}
		})
	}
}
func TestColdCandidateRejectsEveryExistingArtifact(t *testing.T) {
	db := filepath.Join(t.TempDir(), "control.db")
	p, e := DeriveCandidatePaths(db, "restore-plan-a")
	if e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{db, db + "-wal", p.AuthorityLock, p.Candidate, p.Candidate + "-shm", p.PreservedAuthority, p.TransitionJournal} {
		t.Run(filepath.Base(name), func(t *testing.T) {
			if e := os.WriteFile(name, []byte("preserve"), 0600); e != nil {
				t.Fatal(e)
			}
			defer os.Remove(name)
			if absentColdCandidate(db, p) == nil {
				t.Fatal("existing artifact accepted")
			}
			got, _ := os.ReadFile(name)
			if string(got) != "preserve" {
				t.Fatal("artifact modified")
			}
		})
	}
}

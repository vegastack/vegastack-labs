package clientfile

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestReaderPreservesExplicitUnicodeFileBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inventory π.json")
	want := []byte("{\r\n  \"schema\": \"synthetic\"\r\n}\r\n")
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := NewReader().Read(context.Background(), path, MaxInventoryBytes)
	if err != nil || string(got) != string(want) {
		t.Fatalf("Read() = %q, %v", got, err)
	}
}

func TestReaderRejectsUnsafeInputsWithoutPathLeak(t *testing.T) {
	directory := t.TempDir()
	regular := filepath.Join(directory, "private-canary.json")
	if err := os.WriteFile(regular, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link.json")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	hardlink := filepath.Join(directory, "hard.json")
	if err := os.Link(regular, hardlink); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"relative.json", filepath.Join(directory, "..", filepath.Base(directory), "private-canary.json"), directory, link, hardlink} {
		_, err := NewReader().Read(context.Background(), path, MaxInventoryBytes)
		stable, ok := failure.As(err)
		if !ok || stable.Code != generated.ErrorCodeInputInvalid || strings.Contains(err.Error(), "private-canary") {
			t.Fatalf("Read(%q) error = %v", path, err)
		}
	}
}

func TestReaderRejectsEmptyOversizeNonUTF8AndCancellation(t *testing.T) {
	directory := t.TempDir()
	fixtures := map[string][]byte{"empty": {}, "oversize": []byte("12345"), "non-utf8": {0xff}}
	for name, content := range fixtures {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := NewReader().Read(context.Background(), path, 4)
		stable, ok := failure.As(err)
		if !ok || stable.Code != generated.ErrorCodeInputInvalid {
			t.Fatalf("%s error = %v", name, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := NewReader().Read(ctx, filepath.Join(directory, "oversize"), MaxInventoryBytes)
	stable, ok := failure.As(err)
	if !ok || stable.Code != generated.ErrorCodeInterrupted {
		t.Fatalf("cancel error = %v", err)
	}
}

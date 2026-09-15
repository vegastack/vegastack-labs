package onepassword

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/mod/modfile"
)

func TestOfficialSDKTreeIsPinnedAndReviewable(t *testing.T) {
	_, file, _, okay := runtime.Caller(0)
	if !okay {
		t.Fatal("locate dependency test")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "../../.."))
	mod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	sum, err := os.ReadFile(filepath.Join(root, "go.sum"))
	if err != nil {
		t.Fatal(err)
	}
	if !pinnedSDKTree(mod, sum) {
		t.Fatal("reviewed official SDK/dependency tree drifted")
	}
	for _, change := range []struct{ old, new string }{
		{"github.com/1password/onepassword-sdk-go v0.4.1", "github.com/1password/onepassword-sdk-go v0.4.2"},
		{"github.com/extism/go-sdk v1.7.1", "github.com/extism/go-sdk v1.7.2"},
		{"github.com/tetratelabs/wazero v1.11.0", "github.com/tetratelabs/wazero v1.11.1"},
	} {
		mutated := strings.Replace(string(mod), change.old, change.new, 1)
		if mutated == string(mod) || pinnedSDKTree([]byte(mutated), sum) {
			t.Fatalf("dependency drift not caught: %s", change.old)
		}
	}
	mutated := strings.Replace(string(sum), "h1:My/Q2QXemep0I0qHgGrOs7EEzpPh2QZ1/II+S3YqOG0=", "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", 1)
	if mutated == string(sum) || pinnedSDKTree(mod, []byte(mutated)) {
		t.Fatal("module checksum drift not caught")
	}
}

func pinnedSDKTree(mod, sum []byte) bool {
	parsed, err := modfile.Parse("go.mod", mod, nil)
	if err != nil {
		return false
	}
	required := map[string]string{"github.com/1password/onepassword-sdk-go": "v0.4.1", "github.com/extism/go-sdk": "v1.7.1", "github.com/tetratelabs/wazero": "v1.11.0"}
	for _, item := range parsed.Require {
		if version, okay := required[item.Mod.Path]; okay {
			if item.Mod.Version != version {
				return false
			}
			delete(required, item.Mod.Path)
		}
	}
	return len(required) == 0 && strings.Contains(string(sum), "github.com/1password/onepassword-sdk-go v0.4.1 h1:My/Q2QXemep0I0qHgGrOs7EEzpPh2QZ1/II+S3YqOG0=")
}

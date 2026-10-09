//go:build linux || darwin

package debianbaseline

import (
	"context"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func aideNativeFixture(t *testing.T) (*nativeRuntime, generated.DebianBaselineInput, *int) {
	t.Helper()
	root := t.TempDir()
	for _, p := range []string{"etc/vsk-labs/baseline", "var/lib/vsk-labs/baseline"} {
		if e := os.MkdirAll(filepath.Join(root, p), 0700); e != nil {
			t.Fatal(e)
		}
	}
	p := "/etc/vsk-labs/security.conf"
	os.WriteFile(filepath.Join(root, p), []byte("reviewed config"), 0600)
	in := baselineInputFixture()
	in.ControlIDs = []string{"linux.aide-integrity"}
	in.AIDE.ScopePaths = []string{p}
	in.AIDE.ScopeDigest = hostaction.Digest(in.AIDE.ScopePaths)
	in.AIDE.ApprovedChangeDigest = hostaction.Digest(map[string]string{p: digestBytes([]byte("reviewed config"))})
	in.RenderedPolicyDigest = PolicyDigest(in)
	calls := 0
	n := &nativeRuntime{root: root, now: time.Now, run: func(_ context.Context, bin string, args []string, _ []byte) ([]byte, error) {
		if bin != "/usr/bin/aide" {
			return nil, errBaseline
		}
		calls++
		if args[0] == "--init" {
			return nil, os.WriteFile(filepath.Join(root, "var/lib/vsk-labs/baseline/aide.new.db"), []byte("native synthetic database"), 0600)
		}
		if args[0] == "--check" {
			return []byte(`{"added":0,"removed":0,"changed":0}`), nil
		}
		return nil, errBaseline
	}}
	return n, in, &calls
}
func TestAIDEInitializeReturnsCurrentReferenceWithoutChangingInputBinding(t *testing.T) {
	n, in, calls := aideNativeFixture(t)
	digest := hostaction.Digest(in)
	out, e := n.applyAIDE(context.Background(), generated.HostActionBundle{ActionID: "debian.aide.initialize"}, in)
	if e != nil || !out.Changed || *calls != 3 {
		t.Fatal(out, e, *calls)
	}
	if len(out.Measurements) != 1 || out.Measurements[0].Status != "passed" || out.Measurements[0].Baseline.AIDEReferenceDigest != digestBytes([]byte("native synthetic database")) || out.Measurements[0].ConfigurationDigest != digest {
		t.Fatal("reference or immutable input binding lost", out)
	}
	if _, e = os.Stat(filepath.Join(n.root, "var/lib/vsk-labs/baseline/aide.new.db")); !os.IsNotExist(e) {
		t.Fatal("temporary database retained")
	}
	if _, e = n.applyAIDE(context.Background(), generated.HostActionBundle{ActionID: "debian.aide.initialize"}, in); e == nil {
		t.Fatal("initialize overwrote existing reference")
	}
}
func TestAIDEDoesNotBlessUnreviewedScopedFileDrift(t *testing.T) {
	n, in, calls := aideNativeFixture(t)
	os.WriteFile(filepath.Join(n.root, strings.TrimPrefix(in.AIDE.ScopePaths[0], "/")), []byte("unreviewed"), 0600)
	if out, e := n.applyAIDE(context.Background(), generated.HostActionBundle{ActionID: "debian.aide.initialize"}, in); e == nil || out.Changed || *calls != 0 {
		t.Fatal("unreviewed content initialized", out, e, *calls)
	}
}
func TestAIDERefreshRequiresExactPriorDatabase(t *testing.T) {
	n, in, calls := aideNativeFixture(t)
	p := filepath.Join(n.root, "var/lib/vsk-labs/baseline/aide.db")
	os.WriteFile(p, []byte("prior"), 0600)
	in.AIDE.PreviousDigest = hostaction.Digest("different")
	if _, e := n.applyAIDE(context.Background(), generated.HostActionBundle{ActionID: "debian.aide.refresh"}, in); e == nil || *calls != 0 {
		t.Fatal("wrong previous reference accepted")
	}
	b, _ := os.ReadFile(p)
	if string(b) != "prior" {
		t.Fatal("prior DB destroyed")
	}
}

func TestAIDERefusesContentChangedDuringInitialization(t *testing.T) {
	for _, self := range []bool{false, true} {
		t.Run(fmt.Sprint(self), func(t *testing.T) {
			n, in, _ := aideNativeFixture(t)
			if self {
				p := "/etc/vsk-labs/baseline/aide.conf"
				os.WriteFile(filepath.Join(n.root, p), []byte("old"), 0600)
				in.AIDE.ScopePaths = []string{p}
				in.AIDE.ScopeDigest = hostaction.Digest(in.AIDE.ScopePaths)
				in.AIDE.ApprovedChangeDigest = hostaction.Digest(map[string]string{p: digestBytes([]byte("old"))})
			}
			original := n.run
			n.run = func(ctx context.Context, bin string, args []string, b []byte) ([]byte, error) {
				out, e := original(ctx, bin, args, b)
				if args[0] == "--init" && !self {
					os.WriteFile(filepath.Join(n.root, in.AIDE.ScopePaths[0]), []byte("drift"), 0600)
				}
				return out, e
			}
			if _, e := n.applyAIDE(context.Background(), generated.HostActionBundle{ActionID: "debian.aide.initialize"}, in); e == nil {
				t.Fatal("unapproved content promoted")
			}
			for _, p := range []string{"aide.db", "aide-reference.json"} {
				if _, e := os.Stat(filepath.Join(n.root, "var/lib/vsk-labs/baseline", p)); !os.IsNotExist(e) {
					t.Fatal("reference promoted", p)
				}
			}
		})
	}
}

//go:build linux || darwin

package debianbaseline

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"os"
	"path/filepath"
	"testing"
)

func TestAppArmorPreflightsAllProfilesWithoutMutation(t *testing.T) {
	for _, bad := range []bool{false, true} {
		root := t.TempDir()
		os.MkdirAll(filepath.Join(root, "etc/apparmor.d"), 0700)
		raw := []byte("profile first { }\n")
		os.WriteFile(filepath.Join(root, "etc/apparmor.d/first"), raw, 0600)
		in := generated.DebianBaselineInput{ControlIDs: []string{"linux.apparmor-enforcing"}, AppArmorProfiles: []generated.BaselineApparmorProfile{{ProfileID: "first", PackageName: "profiles", ProfileDigest: digestBytes(raw)}}}
		if bad {
			in.AppArmorProfiles = append(in.AppArmorProfiles, generated.BaselineApparmorProfile{ProfileID: "missing", PackageName: "profiles", ProfileDigest: digestBytes(raw)})
		}
		n := &nativeRuntime{root: root, run: func(_ context.Context, bin string, args []string, _ []byte) ([]byte, error) {
			switch bin {
			case "/usr/sbin/aa-status":
				return []byte(`{"profiles":{}}`), nil
			case "/usr/bin/dpkg":
				return nil, nil
			case "/usr/sbin/apparmor_parser":
				if args[0] != "--names" {
					t.Fatal("mutation during preflight")
				}
				return []byte("first"), nil
			}
			return nil, errBaseline
		}}
		p, e := n.preflightProfiles(context.Background(), in)
		if bad {
			if e == nil || len(p) != 0 {
				t.Fatal("partial preflight escaped", p, e)
			}
		} else if e != nil || len(p) != 1 {
			t.Fatal(p, e)
		}
	}
}

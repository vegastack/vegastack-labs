//go:build linux

package server

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHostingProtectedConfigurationRejectsDriftAndUnboundProvider(t *testing.T) {
	root := t.TempDir()
	os.Chmod(root, 0700)
	path := filepath.Join(root, "hosting.json")
	digest := "sha256:" + strings.Repeat("a", 64)
	original := []byte(`{"targets":[{"hostId":"control-a","identityDigest":"` + digest + `","role":"control"}],"platform":{"hostId":"control-a","hostIdentityDigest":"` + digest + `","componentDirectory":"/data/coolify"}}`)
	for _, mode := range []string{"valid", "changed-bytes", "unsafe-mode", "unknown-field", "duplicate-field", "unbound-provider"} {
		t.Run(mode, func(t *testing.T) {
			raw := append([]byte(nil), original...)
			switch mode {
			case "unknown-field":
				raw = []byte(`{"targets":[],"arbitraryCommand":"no"}`)
			case "duplicate-field":
				raw = []byte(`{"targets":[],"targets":[]}`)
			case "unbound-provider":
				raw = []byte(`{"targets":[{"hostId":"control-a","identityDigest":"` + digest + `","role":"control"}],"coolify":{"hostId":"foreign","destinationHostId":"foreign","origin":"https://fixture.invalid","resources":{"teamId":1}}}`)
			}
			if e := os.WriteFile(path, raw, 0600); e != nil {
				t.Fatal(e)
			}
			p := generated.HostingLifecycleProfile{TargetID: "hosting-a", BindingID: "binding-a", ConfigurationPath: path, ConfigurationDigest: hostaction.BytesDigest(raw)}
			q := generated.HostingLifecycleRequest{TargetID: p.TargetID, BindingID: p.BindingID, ConfigurationDigest: p.ConfigurationDigest}
			c := &hostingLifecycleComposition{profiles: map[string]generated.HostingLifecycleProfile{p.TargetID: p}, owner: uint32(os.Geteuid())}
			switch mode {
			case "changed-bytes":
				os.WriteFile(path, []byte(`{"changed":true}`), 0600)
			case "unsafe-mode":
				os.Chmod(path, 0644)
			}
			out, _, e := c.configuration(context.Background(), q)
			if (e == nil) != (mode == "valid") {
				t.Fatal(mode, e)
			}
			if mode == "valid" {
				b, _ := json.Marshal(out)
				if strings.Contains(string(b), "arbitrary") {
					t.Fatal("unvalidated settings")
				}
			}
		})
	}
}

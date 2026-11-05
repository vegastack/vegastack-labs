//go:build linux || darwin

package debianaccess

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/strictjson"
	"os"
	"strings"
)

func (n *nativeRuntime) inspectSudo(ctx context.Context, in generated.DebianAccessInput) error {
	nss, e := n.read("etc/nsswitch.conf")
	if e != nil {
		return e
	}
	for _, line := range strings.Split(string(nss), "\n") {
		f := strings.Fields(strings.SplitN(line, "#", 2)[0])
		if len(f) > 0 && f[0] == "sudoers:" && (len(f) != 2 || f[1] != "files") {
			return errAccess
		}
	}
	config, e := n.read("etc/sudo.conf")
	if e != nil && !os.IsNotExist(e) {
		return e
	}
	for _, line := range strings.Split(string(config), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "" {
			continue
		}
		switch line {
		case "Plugin sudoers_policy sudoers.so", "Plugin sudoers_io sudoers.so", "Plugin sudoers_audit sudoers.so":
		default:
			return errAccess
		}
	}
	for _, a := range in.Accounts {
		raw, e := n.run(ctx, "/usr/bin/cvtsudoers", []string{"-c", "/dev/null", "-f", "json", "-e", "-M", "-m", "user=" + a.Name, "/etc/sudoers"}, nil)
		if e != nil {
			return errAccess
		}
		if retained := a.RetainedAdministrator; retained != nil {
			var policy map[string]json.RawMessage
			if validateRetainedAdministrator(a) != nil || len(raw) > 65536 || strictjson.Scan(ctx, raw, strictjson.Limits{MaxDepth: 12}) != nil || json.Unmarshal(raw, &policy) != nil || policy == nil || digestBytes(raw) != retained.SudoPolicyDigest {
				return errAccess
			}
			continue
		}
		if validateSudoPolicy(raw, a.Name, a.Role == "automation") != nil {
			return errAccess
		}
	}
	return nil
}

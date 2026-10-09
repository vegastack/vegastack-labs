package debianaccess

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/strictjson"
)

// This validates the native converter's bounded JSON for our one supported grant.
// It is not a sudoers parser or a general sudo policy evaluator.
type sudoPolicyJSON struct {
	Defaults []sudoDefaults `json:"Defaults"`
	Users    []sudoUserSpec `json:"User_Specs"`
}
type sudoDefaults struct {
	Binding []map[string]json.RawMessage `json:"Binding,omitempty"`
	Options []map[string]json.RawMessage `json:"Options"`
}
type sudoUserSpec struct {
	Users    []map[string]string `json:"User_List"`
	Hosts    []map[string]string `json:"Host_List"`
	Commands []sudoCommandSpec   `json:"Cmnd_Specs"`
}
type sudoCommandSpec struct {
	RunAsUsers  []map[string]string          `json:"runasusers"`
	RunAsGroups []map[string]string          `json:"runasgroups,omitempty"`
	Options     []map[string]json.RawMessage `json:"Options"`
	Commands    []map[string]string          `json:"Commands"`
}

func validateSudoPolicy(raw []byte, user string, automation bool) error {
	if len(raw) > 65536 || strictjson.Scan(context.Background(), raw, strictjson.Limits{MaxDepth: 12}) != nil {
		return errAccess
	}
	var p sudoPolicyJSON
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil {
		return errAccess
	}
	for _, defaults := range p.Defaults {
		if len(defaults.Binding) != 0 {
			return errAccess
		}
		for _, option := range defaults.Options {
			if len(option) != 1 {
				return errAccess
			}
			for name, v := range option {
				switch name {
				case "env_reset", "mail_badpass", "use_pty":
					if string(v) != "true" {
						return errAccess
					}
				case "secure_path":
					var path string
					if json.Unmarshal(v, &path) != nil || path != "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" {
						return errAccess
					}
				default:
					return errAccess
				}
			}
		}
	}
	if !automation {
		if len(p.Users) != 0 {
			return errAccess
		}
		return nil
	}
	if len(p.Users) != 1 {
		return errAccess
	}
	u := p.Users[0]
	if !singleName(u.Users, "username", user) || !singleName(u.Hosts, "hostname", "ALL") || len(u.Commands) != 1 {
		return errAccess
	}
	c := u.Commands[0]
	if !singleName(c.RunAsUsers, "username", "root") || len(c.RunAsGroups) != 0 || !singleName(c.Commands, "command", "/usr/local/bin/vsk-labs host-action-once") {
		return errAccess
	}
	authenticate := false
	for _, option := range c.Options {
		if len(option) != 1 {
			return errAccess
		}
		for name, v := range option {
			if name == "authenticate" && string(v) == "false" && !authenticate {
				authenticate = true
			} else if name == "setenv" && string(v) == "false" {
			} else {
				return errAccess
			}
		}
	}
	if !authenticate {
		return errAccess
	}
	return nil
}
func singleName(values []map[string]string, key, want string) bool {
	return len(values) == 1 && len(values[0]) == 1 && values[0][key] == want
}

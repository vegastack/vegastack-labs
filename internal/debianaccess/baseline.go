package debianaccess

import (
	"path"
	"strings"
)

func baselineOwnedFile(p string) bool {
	switch p {
	case "etc/fail2ban/jail.d/70-vsk-sshd.local", "etc/fail2ban/action.d/vsk-sshd.conf", "etc/audit/rules.d/70-vsk-security.rules", "etc/audit/auditd.conf", "etc/vsk-labs/baseline/aide.conf":
		return true
	}
	return false
}
func validBaselineServices(v []string) bool {
	if len(v) == 0 || len(v) > 3 {
		return false
	}
	seen := map[string]bool{}
	for _, s := range v {
		if seen[s] {
			return false
		}
		seen[s] = true
		switch s {
		case "fail2ban.service", "auditd.service", "apparmor.service":
		default:
			return false
		}
	}
	return true
}

type BaselineAuditState struct {
	RateLimit    int64 `json:"rateLimit"`
	BacklogLimit int64 `json:"backlogLimit"`
	FailureMode  int64 `json:"failureMode"`
}

func validBaselineProfile(p BaselineProfile) bool {
	name := strings.TrimPrefix(p.File, "etc/apparmor.d/")
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, "/\\ \t\n") && path.Clean(name) == name && p.File == "etc/apparmor.d/"+name && digestRE.MatchString(p.Digest) && (p.Name == name || p.Name == "/"+strings.ReplaceAll(name, ".", "/"))
}

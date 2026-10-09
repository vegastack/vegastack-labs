package debianbaseline

import (
	"context"
	"errors"
	"regexp"
)

var errBaseline = errors.New("Debian baseline prerequisite or integrity check failed")

type ReadOperation string

const (
	ReadConfig           ReadOperation = "config"
	ReadProfile          ReadOperation = "profile"
	ReadDisk             ReadOperation = "disk"
	ReadKernel           ReadOperation = "kernel"
	ReadAPT              ReadOperation = "apt"
	ReadFail2ban         ReadOperation = "fail2ban"
	ReadAuditStatus      ReadOperation = "audit-status"
	ReadAuditRules       ReadOperation = "audit-rules"
	ReadAppArmor         ReadOperation = "apparmor"
	ReadUnit             ReadOperation = "unit"
	ReadPackageIntegrity ReadOperation = "package-integrity"
	ReadPackage          ReadOperation = "package"
	ReadTime             ReadOperation = "time"
	ReadAIDE             ReadOperation = "aide"
)

type ReadRequest struct {
	Operation ReadOperation
	Selector  string
}
type NativeReader interface {
	Read(context.Context, ReadRequest) ([]byte, error)
}

var safeName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.@+-]{0,127}$`)

func readCommand(r ReadRequest) (string, []string, error) {
	switch r.Operation {
	case ReadFail2ban:
		switch r.Selector {
		case "maxretry", "findtime", "bantime", "ignoreip", "ignorecommand", "journalmatch", "logpath", "actions", "usedns":
			return "/usr/bin/fail2ban-client", []string{"get", "sshd", r.Selector}, nil
		case "status":
			return "/usr/bin/fail2ban-client", []string{"status"}, nil
		}
	case ReadAuditStatus:
		if r.Selector == "" {
			return "/usr/sbin/auditctl", []string{"-s"}, nil
		}
	case ReadAuditRules:
		if r.Selector == "" {
			return "/usr/sbin/auditctl", []string{"-l"}, nil
		}
	case ReadAppArmor:
		if r.Selector == "" {
			return "/usr/sbin/aa-status", []string{"--json"}, nil
		}
	case ReadUnit:
		if safeName.MatchString(r.Selector) {
			return "/usr/bin/systemctl", []string{"show", r.Selector, "--property=ActiveState,SubState,MemoryMax,TasksMax,CPUQuotaPerSecUSec,FragmentPath"}, nil
		}
	case ReadPackageIntegrity:
		if safeName.MatchString(r.Selector) {
			return "/usr/bin/dpkg", []string{"--verify", r.Selector}, nil
		}
	case ReadPackage:
		if safeName.MatchString(r.Selector) {
			return "/usr/bin/dpkg-query", []string{"--show", "--showformat=${Version}", r.Selector}, nil
		}
	case ReadTime:
		if r.Selector == "systemd-timesyncd" {
			return "/usr/bin/timedatectl", []string{"show", "--property=NTPSynchronized", "--value"}, nil
		}
		if r.Selector == "chrony" {
			return "/usr/bin/chronyc", []string{"-c", "tracking"}, nil
		}
	case ReadAIDE:
		if r.Selector == "" {
			return "/usr/bin/aide", []string{"--check", "--config=/etc/vsk-labs/baseline/aide.conf"}, nil
		}
	}
	return "", nil, errBaseline
}

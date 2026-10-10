package linuxrole

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"reflect"
	"slices"
)

type RolePreparation = generated.RolePreparation

func AccountName(selector string) string {
	switch selector {
	case "control":
		return "vsk-labs"
	case "application":
		return "vsk-app"
	case "ci":
		return "vsk-ci"
	case "standby":
		return "vsk-standby"
	}
	return ""
}
func UnitName(role string) string {
	switch role {
	case "control":
		return "vsk-labs.service"
	case "application":
		return "vsk-application.slice"
	case "ci":
		return "vsk-ci.slice"
	case "reserve", "recovery-spare":
		return "vsk-standby.slice"
	}
	return ""
}
func DirectoryPath(role, selector string) string {
	if role == "control" {
		switch selector {
		case "config":
			return "etc/vsk-labs/control"
		case "state":
			return "var/lib/vsk-labs/control"
		case "runtime":
			return "run/vsk-labs-control"
		}
		return ""
	}
	base := "vsk-labs"
	switch role {
	case "application":
		base = "vsk-application"
	case "ci":
		base = "vsk-ci"
	case "reserve", "recovery-spare":
		base = "vsk-standby"
	case "control":
	default:
		return ""
	}
	switch selector {
	case "config":
		return "etc/" + base
	case "state":
		return "var/lib/" + base
	case "runtime":
		return "run/" + base
	case "work":
		if role == "application" || role == "ci" {
			return "var/lib/" + base + "/work"
		}
	}
	return ""
}
func TmpfilesPath(role string) string {
	switch role {
	case "application":
		return "etc/tmpfiles.d/vsk-application.conf"
	case "ci":
		return "etc/tmpfiles.d/vsk-ci.conf"
	case "reserve", "recovery-spare":
		return "etc/tmpfiles.d/vsk-standby.conf"
	}
	return ""
}
func DesiredFiles(in generated.LinuxRoleInput) map[string][]byte {
	files := map[string][]byte{}
	unit := UnitName(in.RoleID)
	if unit == "" || len(in.Accounts) != 1 {
		return files
	}
	r := in.Resources
	limits := fmt.Sprintf("MemoryMax=%d\nCPUQuota=%d%%\nTasksMax=%d\n", r.MemoryMaxBytes, r.CPUQuotaPercent, r.TasksMax)
	if in.RoleID == "control" {
		a := in.Accounts[0]

		delivery := ""
		writable := "/var/lib/vsk-labs/control /run/vsk-labs-control"
		if in.ControlLocalBackup {
			writable += " /run/vsk-labs/backup/requests /run/vsk-labs/backup/exchange"
		}
		plain := slices.Clone(in.ControlPlainCredentials)
		encrypted := slices.Clone(in.ControlEncryptedCredentials)
		slices.Sort(plain)
		slices.Sort(encrypted)
		for _, name := range plain {
			delivery += "LoadCredential=" + name + ":/etc/vsk-labs/control/credentials/" + name + "\n"
		}
		for _, name := range encrypted {
			delivery += "LoadCredentialEncrypted=" + name + ":/var/lib/vsk-labs/control/credential-drafts/" + name + "\n"
		}
		files["etc/systemd/system/"+unit] = []byte(fmt.Sprintf("[Unit]\nDescription=VegaStack Labs control service\nAfter=network.target\n[Service]\nType=simple\nUser=%d\nGroup=%d\n%sExecStart=/usr/local/bin/vsk-labs server run --config /etc/vsk-labs/control/server.json\nWorkingDirectory=/var/lib/vsk-labs/control\nRuntimeDirectory=vsk-labs-control\nRuntimeDirectoryMode=0700\nUMask=0077\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nProtectHome=yes\nReadWritePaths=%s\n%sRestart=no\n[Install]\nWantedBy=multi-user.target\n", a.UID, a.GID, delivery, writable, limits))
	} else {
		files["etc/systemd/system/"+unit] = []byte("[Unit]\nDescription=VegaStack Labs role resource boundary\n[Slice]\n" + limits + "[Install]\nWantedBy=multi-user.target\n")
		for _, d := range in.Directories {
			if d.Selector == "runtime" {
				files[TmpfilesPath(in.RoleID)] = []byte(fmt.Sprintf("d /%s %s %d %d -\n", DirectoryPath(in.RoleID, "runtime"), d.Mode, d.UID, d.GID))
			}
		}
	}
	return files
}
func PolicyDigest(in generated.LinuxRoleInput) string { return hostaction.Digest(DesiredFiles(in)) }
func Prepare(in generated.LinuxRoleInput) (RolePreparation, error) {
	in.RenderedPolicyDigest = PolicyDigest(in)
	in.RoleBindingDigest = RoleBindingDigest(in)
	if e := ValidateDesiredInput(in); e != nil {
		return RolePreparation{}, e
	}
	p := RolePreparation{Schema: generated.SchemaIDRolePreparation, SchemaVersion: "1.0.0", Input: in, Files: preparedFiles(in), PolicyDigest: PolicyDigest(in), Steps: []string{"Administrator verifies the exact existing account UID/GID, protected paths and public-key trust; conflicting identities or unknown data must be preserved.", "Use the existing server, exact role plan and human acknowledgement to install these inert files; preparation performs no filesystem or database writes.", "Recollect the affected baseline and role observations before requesting workload admission; provider enrollment and native qualification remain separate."}}
	a := in.Accounts[0]
	p.Steps = append(p.Steps, fmt.Sprintf("Administrator prerequisite: establish or verify account %s with UID %d and GID %d; refuse conflicting names, IDs or supplementary privileges.", AccountName(a.Selector), a.UID, a.GID))
	for _, d := range in.Directories {
		p.Steps = append(p.Steps, fmt.Sprintf("Verify /%s has exact owner UID %d/GID %d and mode %s, with protected parent directories; refuse symlinks and unknown data instead of recursive ownership changes.", DirectoryPath(in.RoleID, d.Selector), d.UID, d.GID, d.Mode))
	}
	if in.RoleID == "control" {
		p.Steps = append(p.Steps, "Run foreground server setup as the same non-root service UID with the verified executable and protected configuration; only the server creates SQLite.", "A separately acknowledged exact control handoff and fresh acknowledged verification are required; installing the unit does not start or stop the foreground server.")
	}
	return p, nil
}
func ValidatePreparation(p RolePreparation) error {
	expected, e := Prepare(p.Input)
	if e != nil {
		return e
	}
	if !reflect.DeepEqual(p, expected) {
		return errInput
	}
	return nil
}

func preparedFiles(in generated.LinuxRoleInput) []generated.RolePreparedFile {
	files := DesiredFiles(in)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	slices.Sort(names)
	out := make([]generated.RolePreparedFile, 0, len(names))
	for _, name := range names {
		sum := sha256.Sum256(files[name])
		out = append(out, generated.RolePreparedFile{Schema: generated.SchemaIDRolePreparedFile, SchemaVersion: "1.0.0", Path: name, Content: string(files[name]), Digest: "sha256:" + hex.EncodeToString(sum[:])})
	}
	return out
}

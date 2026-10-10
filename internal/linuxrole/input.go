// Package linuxrole prepares finite Linux role foundations without local effects.
package linuxrole

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/vegastack/vegastack-labs/internal/debianaccess"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/strictjson"
	"regexp"
	"slices"
	"strings"
	"time"
)

const MaximumInput = 32768
const ActionVersion = "1.0.0"

var errInput = errors.New("invalid Linux role input")
var controlCredentialName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,126}$`)
var controlEncryptedName = regexp.MustCompile(`^credential-[a-f0-9]{32}$`)
var ControlIDs = []string{"linux.role-identity-paths", "linux.role-service-resources", "linux.role-network-boundary", "linux.role-workload-isolation", "linux.control-service", "linux.reserve-no-workloads"}

func decode(raw []byte) (generated.LinuxRoleInput, error) {
	var in generated.LinuxRoleInput
	if len(raw) == 0 || len(raw) > MaximumInput || strictjson.Scan(context.Background(), raw, strictjson.Limits{MaxDepth: 16}) != nil || generated.ValidateContractJSON(generated.SchemaIDLinuxRoleInput, raw, generated.ContractExact) != nil || json.Unmarshal(raw, &in) != nil {
		return in, errInput
	}
	return in, nil
}
func DecodeInput(raw []byte) (generated.LinuxRoleInput, error) {
	in, e := decode(raw)
	if e != nil {
		return in, e
	}
	return in, ValidateInput(in)
}
func DecodeDesiredInput(raw []byte) (generated.LinuxRoleInput, error) {
	in, e := decode(raw)
	if e != nil {
		return in, e
	}
	return in, ValidateDesiredInput(in)
}
func ValidateInput(in generated.LinuxRoleInput) error {
	if in.BaselineSnapshotDigest == "" || in.RenderedPolicyDigest != PolicyDigest(in) || in.RoleBindingDigest != RoleBindingDigest(in) {
		return errInput
	}
	return ValidateDesiredInput(in)
}
func ValidateDesiredInput(in generated.LinuxRoleInput) error {
	raw, e := json.Marshal(in)
	if e != nil {
		return errInput
	}
	if _, e = decode(raw); e != nil {
		return e
	}
	if debianaccess.ProtectedName(in.HostID) || in.ActionVersion != ActionVersion || in.AutomationUID < 1 || in.AutomationUID > 4294967295 || in.ProfileLockDigest != hostaction.Digest(in.ProfileLock) || in.ProfileLock.OSFamily != "debian" || in.ProfileLock.OSVersion != "13.6" || in.ProfileLock.Architecture != "amd64" || in.ProfileLock.Backend != "iptables-nft" || len(in.ProfileLock.Packages) == 0 {
		return errInput
	}
	packages := map[string]bool{}
	for _, p := range in.ProfileLock.Packages {
		if packages[p.Name] || p.Version == "" {
			return errInput
		}
		packages[p.Name] = true
	}
	if !packages["systemd"] {
		return errInput
	}
	if in.NetworkingRequired != (in.NetworkAccess != nil) {
		return errInput
	}
	if net := in.NetworkAccess; net != nil {
		if debianaccess.ValidateInput(*net) != nil || net.HostID != in.HostID || net.HostIdentityDigest != in.HostIdentityDigest || net.ProfileID != in.ProfileID || net.ProfileLockDigest != in.ProfileLockDigest || net.AutomationUID != in.AutomationUID {
			return errInput
		}
	}
	account := in.RoleID
	if account == "reserve" || account == "recovery-spare" {
		account = "standby"
	}
	if len(in.Accounts) != 1 {
		return errInput
	}
	a := in.Accounts[0]
	if a.Selector != account || a.UID > 4294967295 || a.GID > 4294967295 || a.UID < 1 || a.GID < 1 {
		return errInput
	}
	if in.RoleID == "control" && (!a.Existing || a.UID != in.AutomationUID) {
		return errInput
	}
	if in.RoleID != "control" && a.UID == in.AutomationUID {
		return errInput
	}
	if account != "standby" && !in.NetworkingRequired {
		return errInput
	}
	if in.StandbyRequired != (account == "standby") {
		return errInput
	}

	if len(in.ControlPlainCredentials)+len(in.ControlEncryptedCredentials) > 16 || in.RoleID != "control" && (len(in.ControlPlainCredentials) > 0 || len(in.ControlEncryptedCredentials) > 0 || in.ControlLocalBackup) {
		return errInput
	}
	names := map[string]bool{}
	for _, name := range in.ControlPlainCredentials {
		if !controlCredentialName.MatchString(name) || names[name] {
			return errInput
		}
		names[name] = true
	}
	for _, name := range in.ControlEncryptedCredentials {
		if !controlEncryptedName.MatchString(name) || names[name] {
			return errInput
		}
		names[name] = true
	}
	r := in.Resources
	if r.MemoryMaxBytes < 16<<20 || r.MemoryMaxBytes > r.CapacityMemoryBytes || r.CapacityMemoryBytes > 1<<50 || r.CPUQuotaPercent > r.CapacityCPUPercent || r.CapacityCPUPercent > 10000 || r.TasksMax > r.CapacityTasks || r.CapacityTasks > 1048576 || r.MinimumFreeBytes < 1<<30 || r.MinimumFreePercent < 10 || r.MinimumFreePercent > 100 {
		return errInput
	}
	dirs := map[string]bool{}
	for _, d := range in.Directories {
		if dirs[d.Selector] || DirectoryPath(in.RoleID, d.Selector) == "" || d.UID != a.UID || d.GID != a.GID || (d.ExpectedState == "absent") != (d.ExpectedDigest == "") {
			return errInput
		}
		dirs[d.Selector] = true
	}
	for _, s := range []string{"config", "state", "runtime"} {
		if !dirs[s] {
			return errInput
		}
	}
	if (in.RoleID == "application" || in.RoleID == "ci") && !dirs["work"] {
		return errInput
	}
	controls := map[string]bool{}
	for _, c := range in.ControlIDs {
		if controls[c] || !slices.Contains(ControlIDs, c) {
			return errInput
		}
		controls[c] = true
		if c == "linux.control-service" && in.RoleID != "control" || c == "linux.reserve-no-workloads" && account != "standby" || c == "linux.role-workload-isolation" && in.RoleID != "application" && in.RoleID != "ci" || c == "linux.role-network-boundary" && !in.NetworkingRequired {
			return errInput
		}
	}
	if len(controls) == 0 {
		return errInput
	}
	affected := map[string]bool{}
	for _, c := range in.AffectedBaselineControlIDs {
		if affected[c] || !slices.Contains([]string{"debian.accounts", "debian.ssh", "debian.host-firewall", "debian.container-firewall", "linux.fail2ban-sshd", "linux.audit-bounded", "linux.apparmor-enforcing", "linux.aide-integrity", "linux.update-health", "linux.time-sync", "linux.resource-health", "linux.kernel-settings"}, c) {
			return errInput
		}
		affected[c] = true
	}
	if !affected["debian.accounts"] || !affected["debian.ssh"] || !affected["linux.resource-health"] || in.NetworkingRequired && !affected["debian.host-firewall"] {
		return errInput
	}
	if in.RoleID == "control" && in.ExpectedTmpfilesDigest != "" {
		return errInput
	}
	if (in.ExpectedServiceState == "absent") != (in.ExpectedUnitDigest == "") {
		return errInput
	}
	if h := in.Handoff; h != nil {
		expiry, ee := time.Parse(time.RFC3339, h.ExpiresAt)
		deadline, de := time.Parse(time.RFC3339, h.RollbackDeadline)
		if in.RoleID != "control" || h.ServiceUID != a.UID || h.ExecutableDigest != in.ExecutableDigest || h.ConfigDigest != in.ConfigDigest || h.UnitDigest != in.ExpectedUnitDigest || h.ForegroundPID < 2 || ee != nil || de != nil || deadline.After(expiry) || deadline.Before(expiry.Add(-10*time.Minute)) {
			return errInput
		}
	}
	return nil
}
func IsAction(id string) bool {
	return slices.Contains([]string{"debian.role.apply", "debian.role.collect", "debian.control.handoff", "debian.control.handoff.verify"}, id)
}
func ScopeForRequest(r generated.HostActionRequest) (*generated.HostRoleScope, error) {
	if !IsAction(r.ActionID) {
		return nil, nil
	}
	raw, e := json.Marshal(r)
	if e != nil || len(raw)+8192 > hostaction.MaximumEnvelope {
		return nil, errInput
	}
	in, e := DecodeInput([]byte(r.ActionInput))
	if e != nil || in.HostID != r.HostID || in.HostIdentityDigest != r.ConsoleConfirmation.HostIdentityDigest || in.AutomationUID != r.CallerUID {
		return nil, errInput
	}
	handoff := r.ActionID == "debian.control.handoff" || r.ActionID == "debian.control.handoff.verify"
	if handoff != (in.Handoff != nil) {
		return nil, errInput
	}
	if in.Handoff != nil && in.Handoff.RecoveryEpoch != r.RecoveryEpoch {
		return nil, errInput
	}
	return &generated.HostRoleScope{Schema: generated.SchemaIDHostRoleScope, SchemaVersion: "1.0.0", SubjectHostID: in.HostID, SubjectIdentityDigest: in.HostIdentityDigest, ExecutionHostID: r.HostID, ExecutionIdentityDigest: in.HostIdentityDigest, ProfileID: in.ProfileID, ProfileLockDigest: in.ProfileLockDigest, RoleID: in.RoleID, ControlIDs: append([]string(nil), in.ControlIDs...), AffectedBaselineControlIDs: append([]string(nil), in.AffectedBaselineControlIDs...), BaselineSnapshotDigest: in.BaselineSnapshotDigest, CurrentRoleBindingDigest: in.CurrentRoleBindingDigest, RoleBindingDigest: in.RoleBindingDigest, NetworkingRequired: in.NetworkingRequired, StandbyRequired: in.StandbyRequired}, nil
}

// RoleBindingDigest identifies desired role policy, independently of invocation
// preimages and selected observations. Collection preserves this exact binding.
func RoleBindingDigest(in generated.LinuxRoleInput) string {
	in.CurrentRoleBindingDigest = ""
	in.RoleBindingDigest = ""
	in.BaselineSnapshotDigest = ""
	in.Handoff = nil
	in.ExpectedServiceState = ""
	in.ExpectedUnitDigest = ""
	in.ExpectedTmpfilesDigest = ""
	in.RenderedPolicyDigest = ""
	in.ControlIDs = nil
	in.AffectedBaselineControlIDs = nil
	in.Accounts = append([]generated.LinuxRoleAccount(nil), in.Accounts...)
	for i := range in.Accounts {
		in.Accounts[i].Existing = false
	}
	in.Directories = append([]generated.LinuxRoleDirectory(nil), in.Directories...)
	for i := range in.Directories {
		in.Directories[i].ExpectedState = ""
		in.Directories[i].ExpectedDigest = ""
	}
	in.ControlPlainCredentials = slices.Clone(in.ControlPlainCredentials)
	slices.Sort(in.ControlPlainCredentials)
	in.ControlEncryptedCredentials = slices.Clone(in.ControlEncryptedCredentials)
	slices.Sort(in.ControlEncryptedCredentials)
	slices.SortFunc(in.Accounts, func(a, b generated.LinuxRoleAccount) int { return strings.Compare(a.Selector, b.Selector) })
	slices.SortFunc(in.Directories, func(a, b generated.LinuxRoleDirectory) int { return strings.Compare(a.Selector, b.Selector) })
	return hostaction.Digest(in)
}

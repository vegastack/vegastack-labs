// Package debianbaseline implements the closed Debian baseline action contract.
package debianbaseline

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/vegastack/vegastack-labs/internal/debianaccess"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/strictjson"
	"net/netip"
	"path"
	"regexp"
	"slices"
	"strings"
)

const MaximumInput = 32768
const ActionVersion = "1.0.0"

var errInput = errors.New("invalid Debian baseline input")
var selector = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)
var uuidPattern = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
var ControlIDs = []string{"linux.fail2ban-sshd", "linux.audit-bounded", "linux.apparmor-enforcing", "linux.aide-integrity", "linux.update-health", "linux.time-sync", "linux.resource-health", "linux.kernel-settings"}

func decodeBaseline(raw []byte, schema string, out any) error {
	if len(raw) == 0 || len(raw) > MaximumInput || strictjson.Scan(context.Background(), raw, strictjson.Limits{MaxDepth: 16}) != nil || generated.ValidateContractJSON(schema, raw, generated.ContractExact) != nil || json.Unmarshal(raw, out) != nil {
		return errInput
	}
	for _, marker := range []string{"{{", "{%", "{#", `\n`, `\r`, `\t`, `\u000`} {
		if strings.Contains(string(raw), marker) {
			return errInput
		}
	}
	return nil
}
func DecodeInput(raw []byte) (generated.DebianBaselineInput, error) {
	var in generated.DebianBaselineInput
	if e := decodeBaseline(raw, generated.SchemaIDDebianBaselineInput, &in); e != nil {
		return in, e
	}
	return in, ValidateInput(in)
}
func DecodeDesiredInput(raw []byte) (generated.DebianBaselineInput, error) {
	var in generated.DebianBaselineInput
	if e := decodeBaseline(raw, generated.SchemaIDDebianBaselineInput, &in); e != nil {
		return in, e
	}
	return in, ValidateDesiredInput(in)
}
func validateBase(host, identity, version string, uid int64, lock generated.DebianProfileLock, digest string) error {
	if host == "" || identity == "" || debianaccess.ProtectedName(host) || version != ActionVersion || uid < 1 || uid > 4294967295 || digest != hostaction.Digest(lock) || lock.OSFamily != "debian" || lock.OSVersion != "13.6" || lock.Architecture != "amd64" || lock.Backend != "iptables-nft" || len(lock.Packages) == 0 {
		return errInput
	}
	return nil
}
func permittedPath(value string) bool {
	if path.Clean(value) != value || strings.ContainsAny(value, " \\\x00\r\n\t*?[]{}$") || value == "/" {
		return false
	}
	for _, p := range []string{"/etc/ssh/", "/etc/sudoers.d/", "/etc/vsk-labs/", "/etc/audit/", "/etc/apparmor.d/"} {
		if strings.HasPrefix(value, p) {
			return true
		}
	}
	return slices.Contains([]string{"/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow", "/etc/sudoers"}, value)
}
func ValidateInput(in generated.DebianBaselineInput) error {
	if in.RenderedPolicyDigest != PolicyDigest(in) {
		return errInput
	}
	return ValidateDesiredInput(in)
}
func ValidateDesiredInput(in generated.DebianBaselineInput) error {
	raw, err := json.Marshal(in)
	var checked generated.DebianBaselineInput
	if err != nil || decodeBaseline(raw, generated.SchemaIDDebianBaselineInput, &checked) != nil {
		return errInput
	}
	if validateBase(in.HostID, in.HostIdentityDigest, in.ActionVersion, in.AutomationUID, in.ProfileLock, in.ProfileLockDigest) != nil || len(in.ControlIDs) < 1 || len(in.ControlIDs) > 8 {
		return errInput
	}
	pins := map[string]bool{}
	for _, p := range in.ProfileLock.Packages {
		if pins[p.Name] || p.Version == "" {
			return errInput
		}
		pins[p.Name] = true
	}
	required := map[string][]string{"linux.fail2ban-sshd": {"fail2ban", "python3-systemd"}, "linux.audit-bounded": {"auditd"}, "linux.apparmor-enforcing": {"apparmor", "apparmor-utils"}, "linux.aide-integrity": {"aide"}, "linux.update-health": {"apt"}, "linux.time-sync": {"systemd"}, "linux.resource-health": {"systemd"}, "linux.kernel-settings": {"procps"}}
	if in.TimeOwner == "chrony" {
		required["linux.time-sync"] = []string{"chrony"}
	}
	if in.UpdateOwner == "unattended-upgrades" {
		required["linux.update-health"] = append(required["linux.update-health"], "unattended-upgrades")
	}
	for _, c := range in.ControlIDs {
		for _, p := range required[c] {
			if !pins[p] {
				return errInput
			}
		}
		if strings.HasPrefix(c, "linux.volume-encryption:") && !pins["cryptsetup-bin"] {
			return errInput
		}
	}
	volumes := map[string]bool{}
	for _, v := range in.Volumes {
		if ValidateVolumeBinding(v) != nil || v.HostID != in.HostID || v.HostIdentityDigest != in.HostIdentityDigest || volumes[v.VolumeID] {
			return errInput
		}
		volumes[v.VolumeID] = true
	}
	seen := map[string]bool{}
	for _, id := range in.ControlIDs {
		if seen[id] {
			return errInput
		}
		seen[id] = true
		if !slices.Contains(ControlIDs, id) {
			v, ok := strings.CutPrefix(id, "linux.volume-encryption:")
			if !ok || !volumes[v] {
				return errInput
			}
		}
		if id == "linux.aide-integrity" && in.RoleID != "control" {
			return errInput
		}
	}
	if len(in.RecoverySourcePrefixes) == 0 {
		return errInput
	}
	for _, raw := range in.RecoverySourcePrefixes {
		p, e := netip.ParsePrefix(raw)
		if e != nil || p.Masked().String() != raw || p.Bits() == 0 {
			return errInput
		}
	}
	for _, p := range in.AuditPaths {
		if !permittedPath(p) {
			return errInput
		}
	}
	for _, p := range in.AIDE.ScopePaths {
		if !permittedPath(p) {
			return errInput
		}
	}
	if in.AIDE.ScopeDigest != hostaction.Digest(in.AIDE.ScopePaths) {
		return errInput
	}
	profiles := map[string]bool{}
	for _, p := range in.AppArmorProfiles {
		if !selector.MatchString(p.ProfileID) || !selector.MatchString(p.PackageName) || !selector.MatchString(p.AllowedProbeSelector) || !selector.MatchString(p.DeniedProbeSelector) || profiles[p.ProfileID] {
			return errInput
		}
		profiles[p.ProfileID] = true
		found := false
		for _, pkg := range in.ProfileLock.Packages {
			found = found || pkg.Name == p.PackageName
		}
		if !found {
			return errInput
		}
	}
	for _, r := range in.Resources {
		if !strings.HasSuffix(r.Unit, ".service") || !selector.MatchString(r.Unit) || r.MinimumFreeBytes < 1<<30 || r.MinimumFreePercent < 10 || r.MinimumFreePercent > 100 || r.CPUQuotaPercent > 10000 || !validMount(r.MountPath) {
			return errInput
		}
	}
	for _, k := range in.KernelSettings {
		if !slices.Contains([]string{"kernel.dmesg_restrict", "kernel.kptr_restrict", "kernel.yama.ptrace_scope", "fs.protected_hardlinks", "fs.protected_symlinks"}, k.Name) || (k.Value != "1" && !((k.Name == "kernel.kptr_restrict" || k.Name == "kernel.yama.ptrace_scope") && k.Value == "2")) {
			return errInput
		}
	}
	return nil
}
func validMount(p string) bool {
	return strings.HasPrefix(p, "/") && path.Clean(p) == p && !strings.ContainsAny(p, "\x00\r\n\t*?[]{}$")
}
func ValidateVolumeBinding(v generated.HostVolumeBinding) error {
	raw, err := json.Marshal(v)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDHostVolumeBinding, raw, generated.ContractExact) != nil {
		return errInput
	}
	if !selector.MatchString(v.VolumeID) || !selector.MatchString(v.MapperName) || !uuidPattern.MatchString(v.LUKSUUID) || !validMount(v.MountPath) || v.HeaderBytes < 4096 || v.HeaderBytes > 16<<20 || v.KeySlot < 0 || v.KeySlot > 31 || v.HostID == v.RecoveryCustodianID || v.ControlHostID == v.RecoveryCustodianID || v.RecoveryCustodianIdentityDigest == v.HostIdentityDigest || v.RecoveryCustodianIdentityDigest == v.ControlHostIdentityDigest || v.RecoveryEpoch < 0 {
		return errInput
	}
	for _, id := range []string{v.HostID, v.ControlHostID, v.RecoveryCustodianID} {
		if debianaccess.ProtectedName(id) {
			return errInput
		}
	}
	return nil
}
func DecodeRecoveryInput(raw []byte) (generated.VolumeRecoveryInput, error) {
	var in generated.VolumeRecoveryInput
	if e := decodeBaseline(raw, generated.SchemaIDVolumeRecoveryInput, &in); e != nil {
		return in, e
	}
	if validateBase(in.HostID, in.HostIdentityDigest, in.ActionVersion, in.AutomationUID, in.ProfileLock, in.ProfileLockDigest) != nil || ValidateVolumeBinding(in.Binding) != nil || in.HostID != in.Binding.RecoveryCustodianID || in.HostIdentityDigest != in.Binding.RecoveryCustodianIdentityDigest || !selector.MatchString(in.RecoveryReferenceID) || !selector.MatchString(in.RecoveryMaterialVersion) {
		return in, errInput
	}
	found := false
	for _, p := range in.ProfileLock.Packages {
		found = found || p.Name == "cryptsetup-bin"
	}
	if !found {
		return in, errInput
	}
	return in, nil
}
func IsAction(id string) bool {
	return slices.Contains([]string{"debian.baseline.apply", "debian.baseline.collect", "debian.aide.initialize", "debian.aide.refresh", "debian.volume.observe", "debian.volume-recovery.verify"}, id)
}
func ScopeForRequest(r generated.HostActionRequest) (*generated.HostBaselineScope, error) {
	if !IsAction(r.ActionID) {
		return nil, nil
	}
	encoded, err := json.Marshal(r)
	if err != nil || len(encoded)+8192 > hostaction.MaximumEnvelope {
		return nil, errInput
	}
	scope := &generated.HostBaselineScope{Schema: generated.SchemaIDHostBaselineScope, SchemaVersion: "1.0.0", ExecutionHostID: r.HostID, ExecutionIdentityDigest: r.ConsoleConfirmation.HostIdentityDigest}
	if r.ActionID == "debian.volume-recovery.verify" {
		in, e := DecodeRecoveryInput([]byte(r.ActionInput))
		if e != nil || in.HostID != r.HostID || in.HostIdentityDigest != scope.ExecutionIdentityDigest || in.AutomationUID != r.CallerUID || in.Binding.RecoveryEpoch != r.RecoveryEpoch {
			return nil, errInput
		}
		scope.SubjectHostID = in.Binding.HostID
		scope.SubjectIdentityDigest = in.Binding.HostIdentityDigest
		scope.ProfileID = in.ProfileID
		scope.ProfileLockDigest = in.ProfileLockDigest
		scope.RoleID = in.RoleID
		scope.ControlIDs = []string{"linux.volume-recovery:" + in.Binding.VolumeID}
		scope.PriorVolumeReceiptDigest = in.PriorVolumeReceiptDigest
		return scope, nil
	}
	in, e := DecodeInput([]byte(r.ActionInput))
	if e != nil || in.HostID != r.HostID || in.HostIdentityDigest != scope.ExecutionIdentityDigest || in.AutomationUID != r.CallerUID {
		return nil, errInput
	}
	for _, volume := range in.Volumes {
		if volume.RecoveryEpoch != r.RecoveryEpoch {
			return nil, errInput
		}
	}
	for _, id := range in.ControlIDs {
		volume := strings.HasPrefix(id, "linux.volume-encryption:")
		if volume != (r.ActionID == "debian.volume.observe") {
			return nil, errInput
		}
	}
	if strings.HasPrefix(r.ActionID, "debian.aide.") {
		if len(in.ControlIDs) != 1 || in.ControlIDs[0] != "linux.aide-integrity" || in.RoleID != "control" || r.ActionID == "debian.aide.initialize" && in.AIDE.PreviousDigest != "" || r.ActionID == "debian.aide.refresh" && (in.AIDE.PreviousDigest == "" || in.AIDE.ApprovedChangeDigest == "") {
			return nil, errInput
		}
	}
	scope.SubjectHostID = in.HostID
	scope.SubjectIdentityDigest = in.HostIdentityDigest
	scope.ProfileID = in.ProfileID
	scope.ProfileLockDigest = in.ProfileLockDigest
	scope.RoleID = in.RoleID
	scope.ControlIDs = append([]string(nil), in.ControlIDs...)
	return scope, nil
}

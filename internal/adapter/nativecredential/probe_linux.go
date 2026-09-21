//go:build linux

package nativecredential

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	accessProbeMode      = "__native-credential-access-probe"
	accessProbeChildMode = "__native-credential-access-probe-child"
	policyCheckMode      = "__native-credential-policy-check"
	defaultNativeBinary  = "/usr/local/bin/vsk-labs"
	nsenterBinary        = "/usr/bin/nsenter"
	probePolicyPath      = "/etc/vsk-labs/native-credential-authority.json"
	probeInputLimit      = 4096
	probePolicyLimit     = 32768
)

var (
	unitNamePattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@-]{0,126}\.service$`)
	credentialNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,126}$`)
	bootIDPattern         = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	machineIDPattern      = regexp.MustCompile(`^[0-9a-f]{32}$`)
	errProbeBlocked       = errors.New("native credential access prerequisite blocked")
)

type AccessProbeRequest struct {
	UID               uint32 `json:"uid"`
	GID               uint32 `json:"gid"`
	UnitName          string `json:"unit_name"`
	CredentialName    string `json:"credential_name"`
	MainPID           int    `json:"main_pid"`
	ProcessStartTicks uint64 `json:"process_start_ticks"`
	BootID            string `json:"boot_id"`
}

func (r AccessProbeRequest) Validate() error {
	if r.UID == 0 || r.GID == 0 || r.UID > 0x7fffffff || r.GID > 0x7fffffff || r.MainPID <= 1 || r.ProcessStartTicks == 0 ||
		!unitNamePattern.MatchString(r.UnitName) || strings.Contains(r.UnitName, "@.service") || strings.Contains(r.UnitName, "..") ||
		!credentialNamePattern.MatchString(r.CredentialName) || strings.Contains(r.CredentialName, "..") || !bootIDPattern.MatchString(r.BootID) {
		return errProbeBlocked
	}
	return nil
}

type AccessProbeStatus string

const (
	AccessProbeDenied  AccessProbeStatus = "denied"
	AccessProbeOpened  AccessProbeStatus = "opened"
	AccessProbeUnknown AccessProbeStatus = "unknown"
)

type AccessProbeResult struct {
	Status   AccessProbeStatus `json:"status"`
	Device   uint64            `json:"device,omitempty"`
	Inode    uint64            `json:"inode,omitempty"`
	OwnerUID uint32            `json:"owner_uid,omitempty"`
	OwnerGID uint32            `json:"owner_gid,omitempty"`
	Mode     uint32            `json:"mode,omitempty"`
}

func decodeAccessProbeRequest(input io.Reader) (AccessProbeRequest, error) {
	data, err := io.ReadAll(io.LimitReader(input, probeInputLimit+1))
	if err != nil || len(data) > probeInputLimit {
		return AccessProbeRequest{}, errProbeBlocked
	}
	var request AccessProbeRequest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF || request.Validate() != nil {
		return AccessProbeRequest{}, errProbeBlocked
	}
	return request, nil
}

func encodeProbeRequest(request AccessProbeRequest) ([]byte, error) {
	if request.Validate() != nil {
		return nil, errProbeBlocked
	}
	data, err := json.Marshal(request)
	if err != nil || len(data) > probeInputLimit {
		return nil, errProbeBlocked
	}
	return data, nil
}

// ProbeReader requests the fixed sudoers entry. An unqualified local profile is unavailable.
func ProbeReader(ctx context.Context, request AccessProbeRequest) (AccessProbeResult, error) {
	return probeReaderWithBinary(ctx, request, defaultNativeBinary)
}

func probeReaderWithBinary(ctx context.Context, request AccessProbeRequest, binary string) (AccessProbeResult, error) {
	data, err := encodeProbeRequest(request)
	if err != nil || ctx == nil || ctx.Err() != nil || binary != defaultNativeBinary {
		return AccessProbeResult{}, errProbeBlocked
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(bounded, "/usr/bin/sudo", "-n", "--", binary, accessProbeMode)
	cmd.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin"}
	cmd.Stdin = bytes.NewReader(data)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if cmd.Run() != nil || stderr.Len() != 0 || stdout.Len() > 512 || bounded.Err() != nil {
		return AccessProbeResult{}, errProbeBlocked
	}
	var result AccessProbeResult
	decoder := json.NewDecoder(&stdout)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || decoder.Decode(new(any)) != io.EOF || !validProbeResult(result) {
		return AccessProbeResult{}, errProbeBlocked
	}
	if result.Status == AccessProbeUnknown {
		return AccessProbeResult{}, errProbeBlocked
	}
	return result, nil
}

func validProbeResult(result AccessProbeResult) bool {
	if result.Status != AccessProbeDenied && result.Status != AccessProbeOpened && result.Status != AccessProbeUnknown {
		return false
	}
	if result.Status == AccessProbeOpened {
		return result.Device != 0 && result.Inode != 0 && result.Mode&unix.S_IFMT == unix.S_IFREG
	}
	return result.Device == 0 && result.Inode == 0 && result.OwnerUID == 0 && result.OwnerGID == 0 && result.Mode == 0
}

// RunAccessProbeMode is the sole root entry. It accepts one bounded structured stdin request.
func RunAccessProbeMode(ctx context.Context, input io.Reader, output io.Writer) int {
	if os.Geteuid() != 0 || os.Getuid() != 0 || ctx == nil || ctx.Err() != nil {
		return 2
	}
	request, err := decodeAccessProbeRequest(input)
	if err != nil {
		return 2
	}
	if !enrolledProbeRequest(request) {
		return 2
	}
	if verifyTargetProcess(request) != nil {
		return 2
	}
	nsFD, err := unix.Open(fmt.Sprintf("/proc/%d/ns/mnt", request.MainPID), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return 2
	}
	nsFile := os.NewFile(uintptr(nsFD), "target-mount-namespace")
	defer nsFile.Close()
	if verifyPinnedNamespace(request.MainPID, nsFD) != nil {
		return 2
	}
	binaryFD, err := openTrustedExecutable(defaultNativeBinary)
	if err != nil {
		return 2
	}
	defer binaryFD.Close()
	nsenterFD, err := openTrustedExecutable(nsenterBinary)
	if err != nil {
		return 2
	}
	defer nsenterFD.Close()
	data, _ := encodeProbeRequest(request)
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	// Execute the root-owned inode we inspected, not a second path lookup.
	cmd := exec.CommandContext(bounded, fmt.Sprintf("/proc/self/fd/%d", nsenterFD.Fd()),
		"--mount=/proc/self/fd/3", "--setgid="+strconv.FormatUint(uint64(request.GID), 10),
		"--setuid="+strconv.FormatUint(uint64(request.UID), 10), "--", "/proc/self/fd/4", accessProbeChildMode)
	cmd.ExtraFiles = []*os.File{nsFile, binaryFD}
	cmd.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin"}
	cmd.Stdin = bytes.NewReader(data)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if cmd.Run() != nil || stderr.Len() != 0 || stdout.Len() > 512 || bounded.Err() != nil || verifyTargetProcess(request) != nil || verifyPinnedNamespace(request.MainPID, nsFD) != nil || !enrolledProbeRequest(request) {
		return 2
	}
	var result AccessProbeResult
	decoder := json.NewDecoder(&stdout)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || decoder.Decode(new(any)) != io.EOF || !validProbeResult(result) || result.Status == AccessProbeUnknown {
		return 2
	}
	encoded, _ := json.Marshal(result)
	if _, err := output.Write(append(encoded, '\n')); err != nil {
		return 2
	}
	return 0
}

func RunAccessProbeChildMode(input io.Reader, output io.Writer) int {
	request, err := decodeAccessProbeRequest(input)
	if err != nil {
		return 2
	}
	groups, err := os.Getgroups()
	if err != nil || len(groups) != 0 || os.Getuid() != int(request.UID) || os.Geteuid() != int(request.UID) || os.Getgid() != int(request.GID) || os.Getegid() != int(request.GID) {
		return 2
	}
	if !noEffectiveCapabilities() {
		return 2
	}
	result := probeCredentialFile(request.UnitName, request.CredentialName)
	if result.Status == AccessProbeUnknown {
		return 2
	}
	encoded, _ := json.Marshal(result)
	if _, err := output.Write(append(encoded, '\n')); err != nil {
		return 2
	}
	return 0
}

func probeCredentialFile(unit, name string) AccessProbeResult {
	return probeCredentialFileAt("/run/credentials", unit, name)
}

func probeCredentialFileAt(root, unit, name string) AccessProbeResult {
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return probeError(err)
	}
	defer unix.Close(rootFD)
	unitFD, err := unix.Openat(rootFD, unit, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return probeError(err)
	}
	defer unix.Close(unitFD)
	fileFD, err := unix.Openat(unitFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return probeError(err)
	}
	defer unix.Close(fileFD)
	var stat unix.Stat_t
	if unix.Fstat(fileFD, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 {
		return AccessProbeResult{Status: AccessProbeUnknown}
	}
	checkFD, err := unix.Openat(unitFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return AccessProbeResult{Status: AccessProbeUnknown}
	}
	defer unix.Close(checkFD)
	var check unix.Stat_t
	if unix.Fstat(checkFD, &check) != nil || check.Dev != stat.Dev || check.Ino != stat.Ino || check.Mode != stat.Mode || check.Uid != stat.Uid || check.Gid != stat.Gid {
		return AccessProbeResult{Status: AccessProbeUnknown}
	}
	return AccessProbeResult{Status: AccessProbeOpened, Device: uint64(stat.Dev), Inode: stat.Ino, OwnerUID: stat.Uid, OwnerGID: stat.Gid, Mode: stat.Mode}
}

func probeError(err error) AccessProbeResult {
	if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) {
		return AccessProbeResult{Status: AccessProbeDenied}
	}
	return AccessProbeResult{Status: AccessProbeUnknown}
}

func verifyTargetProcess(request AccessProbeRequest) error {
	if !systemdUnitRootSafe(request.UnitName) {
		return errProbeBlocked
	}
	if !systemdMainPIDMatches(request.UnitName, request.MainPID) {
		return errProbeBlocked
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || strings.TrimSpace(string(boot)) != request.BootID {
		return errProbeBlocked
	}
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", request.MainPID))
	if err != nil {
		return errProbeBlocked
	}
	end := bytes.LastIndexByte(stat, ')')
	if end < 0 || end+2 >= len(stat) {
		return errProbeBlocked
	}
	fields := strings.Fields(string(stat[end+2:]))
	if len(fields) <= 19 {
		return errProbeBlocked
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || start != request.ProcessStartTicks {
		return errProbeBlocked
	}
	cgroup, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", request.MainPID))
	if err != nil || !cgroupContainsExactUnit(string(cgroup), request.UnitName) {
		return errProbeBlocked
	}
	return nil
}

func systemdUnitRootSafe(unit string) bool {
	if !unitNamePattern.MatchString(unit) {
		return false
	}
	trusted, err := openTrustedExecutable("/usr/bin/systemctl")
	if err != nil {
		return false
	}
	defer trusted.Close()
	bounded, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(bounded, "/usr/bin/systemctl", "--system", "show", "--property=RootDirectory", "--property=RootImage", unit)
	cmd.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin"}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	return cmd.Run() == nil && bounded.Err() == nil && stderr.Len() == 0 && stdout.Len() <= 256 && parseSystemdRootProfile(stdout.String())
}

func parseSystemdRootProfile(output string) bool {
	if !strings.HasSuffix(output, "\n") {
		return false
	}
	lines := strings.Split(strings.TrimSuffix(output, "\n"), "\n")
	if len(lines) != 2 {
		return false
	}
	seen := map[string]bool{}
	for _, line := range lines {
		key, value, found := strings.Cut(line, "=")
		if !found || value != "" || (key != "RootDirectory" && key != "RootImage") || seen[key] {
			return false
		}
		seen[key] = true
	}
	return seen["RootDirectory"] && seen["RootImage"]
}

func systemdMainPIDMatches(unit string, pid int) bool {
	if !unitNamePattern.MatchString(unit) || pid <= 1 {
		return false
	}
	bounded, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(bounded, "/usr/bin/systemctl", "--system", "show", "--property=MainPID", "--value", unit)
	cmd.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin"}
	cmd.Stdout = nil
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if cmd.Run() != nil || bounded.Err() != nil || stderr.Len() != 0 || stdout.Len() > 32 {
		return false
	}
	actual, err := strconv.Atoi(strings.TrimSpace(stdout.String()))
	return err == nil && actual == pid
}

func cgroupContainsExactUnit(data, unit string) bool {
	for _, line := range strings.Split(data, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		for _, segment := range strings.Split(parts[2], "/") {
			if segment == unit {
				return true
			}
		}
	}
	return false
}

func verifyPinnedNamespace(pid, fd int) error {
	var pinned, current unix.Stat_t
	if unix.Fstat(fd, &pinned) != nil {
		return errProbeBlocked
	}
	currentFD, err := unix.Open(fmt.Sprintf("/proc/%d/ns/mnt", pid), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return errProbeBlocked
	}
	defer unix.Close(currentFD)
	if unix.Fstat(currentFD, &current) != nil || pinned.Dev != current.Dev || pinned.Ino != current.Ino {
		return errProbeBlocked
	}
	return nil
}

func openTrustedExecutable(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !trustedParentDirectories(path) {
		return nil, errProbeBlocked
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errProbeBlocked
	}
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != 0 || stat.Mode&0o022 != 0 || stat.Mode&0o111 == 0 {
		unix.Close(fd)
		return nil, errProbeBlocked
	}
	return os.NewFile(uintptr(fd), "trusted-executable"), nil
}

func noEffectiveCapabilities() bool {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")) == "0000000000000000"
		}
	}
	return false
}

func enrolledProbeRequest(request AccessProbeRequest) bool {
	policy, err := readProbePolicy(probePolicyPath)
	if err != nil {
		return false
	}
	machine, err := os.ReadFile("/etc/machine-id")
	if err != nil || strings.TrimSpace(string(machine)) != policy.MachineID {
		return false
	}
	unitFound := false
	for _, allowed := range policy.Units {
		if allowed == request.UnitName {
			unitFound = true
			break
		}
	}
	if !unitFound {
		return false
	}
	for _, allowed := range policy.Probes {
		if allowed.UnitName == request.UnitName && allowed.CredentialName == request.CredentialName && allowed.UID == request.UID && allowed.GID == request.GID {
			return true
		}
	}
	return false
}

type probePolicy struct {
	Version   int               `json:"version"`
	MachineID string            `json:"machine_id"`
	Units     []string          `json:"units"`
	Probes    []probeEnrollment `json:"probes"`
}

type probeEnrollment struct {
	UnitName       string `json:"unit_name"`
	CredentialName string `json:"credential_name"`
	UID            uint32 `json:"uid"`
	GID            uint32 `json:"gid"`
}

func readProbePolicy(path string) (probePolicy, error) {
	if !trustedParentDirectories(path) {
		return probePolicy{}, errProbeBlocked
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return probePolicy{}, errProbeBlocked
	}
	file := os.NewFile(uintptr(fd), "native-probe-policy")
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != 0 || stat.Mode&0o777&^0o640 != 0 || stat.Mode&0o400 == 0 || stat.Nlink != 1 || stat.Size > probePolicyLimit {
		return probePolicy{}, errProbeBlocked
	}
	data, err := io.ReadAll(io.LimitReader(file, probePolicyLimit+1))
	if err != nil || len(data) > probePolicyLimit {
		return probePolicy{}, errProbeBlocked
	}
	return parseProbePolicy(data)
}

func parseProbePolicy(data []byte) (probePolicy, error) {
	var policy probePolicy
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&policy) != nil || decoder.Decode(new(any)) != io.EOF || policy.Version != 1 || !machineIDPattern.MatchString(policy.MachineID) || len(policy.Units) == 0 || len(policy.Units) > 64 || len(policy.Probes) == 0 || len(policy.Probes) > 256 {
		return probePolicy{}, errProbeBlocked
	}
	last := ""
	for _, unit := range policy.Units {
		if !unitNamePattern.MatchString(unit) || strings.Contains(unit, "@.service") || strings.Contains(unit, "..") || unit <= last {
			return probePolicy{}, errProbeBlocked
		}
		last = unit
	}
	last = ""
	for _, probe := range policy.Probes {
		key := fmt.Sprintf("%s\x00%s\x00%010d\x00%010d", probe.UnitName, probe.CredentialName, probe.UID, probe.GID)
		if key <= last || probe.UID == 0 || probe.GID == 0 || probe.UID > 0x7fffffff || probe.GID > 0x7fffffff || !credentialNamePattern.MatchString(probe.CredentialName) || strings.Contains(probe.CredentialName, "..") {
			return probePolicy{}, errProbeBlocked
		}
		found := false
		for _, unit := range policy.Units {
			if unit == probe.UnitName {
				found = true
				break
			}
		}
		if !found {
			return probePolicy{}, errProbeBlocked
		}
		last = key
	}
	return policy, nil
}

func trustedParentDirectories(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		var stat unix.Stat_t
		if unix.Lstat(parent, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != 0 || stat.Mode&0o022 != 0 {
			return false
		}
		if parent == "/" {
			break
		}
	}
	return true
}

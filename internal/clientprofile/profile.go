// Package clientprofile loads the portable, non-secret constrained-SSH client
// profile used when the control service is not on the operator's machine.
package clientprofile

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/principal"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

const (
	maximumProfileBytes   = 64 * 1024
	maximumKnownHostsSize = 4 << 20
	maximumExecutableSize = 512 << 20
)

var destinationPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+@[A-Za-z0-9._:-]+$`)

type document struct {
	Schema        string    `json:"schema"`
	SchemaVersion string    `json:"schemaVersion"`
	Transport     transport `json:"transport"`
}

type transport struct {
	Kind           string `json:"kind"`
	Executable     string `json:"executable"`
	Destination    string `json:"destination"`
	KnownHostsPath string `json:"knownHostsPath"`
	SSHPrincipalID string `json:"sshPrincipalId"`
	DeviceID       string `json:"deviceId"`
	RecoveryEpoch  int64  `json:"recoveryEpoch"`
}

// Load returns matched=false when path is not a client profile, allowing the
// existing protected server-profile loader to remain the local path owner.
func Load(ctx context.Context, path string) (serverconfig.Profile, bool, error) {
	if ctx == nil || ctx.Err() != nil {
		return serverconfig.Profile{}, true, failure.New(generated.ErrorCodeInterrupted, "client-profile", false)
	}
	if !validConfiguredPath(path) {
		return serverconfig.Profile{}, true, invalid()
	}
	before, err := os.Lstat(path)
	if err != nil {
		return serverconfig.Profile{}, false, nil
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() < 1 || before.Size() > maximumProfileBytes {
		return serverconfig.Profile{}, true, invalid()
	}
	file, err := os.Open(path)
	if err != nil {
		return serverconfig.Profile{}, true, invalid()
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return serverconfig.Profile{}, true, invalid()
	}
	content, err := io.ReadAll(io.LimitReader(file, maximumProfileBytes+1))
	if err != nil || len(content) == 0 || len(content) > maximumProfileBytes {
		return serverconfig.Profile{}, true, invalid()
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, after) || opened.Size() != after.Size() || int64(len(content)) != opened.Size() {
		return serverconfig.Profile{}, true, invalid()
	}
	var probe struct {
		Schema string `json:"schema"`
	}
	if json.Unmarshal(content, &probe) != nil || probe.Schema != "vegastack-labs.dev/client-profile" {
		return serverconfig.Profile{}, false, nil
	}
	content, err = readTrustedProfile(path)
	if err != nil {
		return serverconfig.Profile{}, true, invalid()
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var profile document
	if decoder.Decode(&profile) != nil {
		return serverconfig.Profile{}, true, invalid()
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF || profile.Schema != "vegastack-labs.dev/client-profile" || profile.SchemaVersion != "1.0.0" || profile.Transport.Kind != "constrained-ssh" ||
		!validExecutablePath(profile.Transport.Executable) ||
		!destinationPattern.MatchString(profile.Transport.Destination) || len(profile.Transport.Destination) > 255 ||
		!principal.ValidID(profile.Transport.SSHPrincipalID) || !principal.ValidID(profile.Transport.DeviceID) || profile.Transport.RecoveryEpoch < 0 ||
		!validConfiguredPath(profile.Transport.KnownHostsPath) {
		return serverconfig.Profile{}, true, invalid()
	}
	if err := validateKnownHosts(profile.Transport.KnownHostsPath); err != nil {
		return serverconfig.Profile{}, true, err
	}
	if err := validateExecutable(profile.Transport.Executable); err != nil {
		return serverconfig.Profile{}, true, err
	}
	arguments := constrainedSSHArguments(profile.Transport.KnownHostsPath, profile.Transport.Destination)
	return serverconfig.Profile{ConstrainedSSH: &serverconfig.ConstrainedSSH{
		Executable: profile.Transport.Executable, Arguments: arguments,
		SSHPrincipalID: profile.Transport.SSHPrincipalID, DeviceID: profile.Transport.DeviceID, RecoveryEpoch: profile.Transport.RecoveryEpoch,
	}}, true, nil
}

type ancestorSnapshot []os.FileInfo

func validConfiguredPath(path string) bool {
	return len(path) >= 2 && len(path) <= 4096 && !strings.ContainsRune(path, 0) &&
		filepath.IsAbs(path) && filepath.Clean(path) == path && path != string(filepath.Separator)
}

func validKnownHostsPath(path string) bool {
	return validConfiguredPath(path) && !strings.ContainsAny(path, "%$\"'\\ \t\r\n\v\f")
}

func snapshotTrustedAncestors(path string) (ancestorSnapshot, bool) {
	paths := ancestorDirectories(path)
	snapshot := make(ancestorSnapshot, 0, len(paths))
	for _, directory := range paths {
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !trustedDirectory(directory, info) {
			return nil, false
		}
		snapshot = append(snapshot, info)
	}
	return snapshot, true
}

func (snapshot ancestorSnapshot) stillTrusted(path string) bool {
	current, ok := snapshotTrustedAncestors(path)
	if !ok || len(current) != len(snapshot) {
		return false
	}
	for index := range snapshot {
		if !os.SameFile(snapshot[index], current[index]) {
			return false
		}
	}
	return true
}

func ancestorDirectories(path string) []string {
	directories := make([]string, 0, 16)
	for directory := filepath.Dir(path); ; directory = filepath.Dir(directory) {
		directories = append(directories, directory)
		if parent := filepath.Dir(directory); parent == directory {
			break
		}
	}
	for left, right := 0, len(directories)-1; left < right; left, right = left+1, right-1 {
		directories[left], directories[right] = directories[right], directories[left]
	}
	return directories
}

func readTrustedProfile(path string) ([]byte, error) {
	ancestors, ok := snapshotTrustedAncestors(path)
	if !ok {
		return nil, invalid()
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() < 1 || before.Size() > maximumProfileBytes || !trustedFile(path, before) {
		return nil, invalid()
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, invalid()
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || !trustedFile(path, opened) {
		return nil, invalid()
	}
	content, err := io.ReadAll(io.LimitReader(file, maximumProfileBytes+1))
	if err != nil || len(content) == 0 || len(content) > maximumProfileBytes {
		return nil, invalid()
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, after) || opened.Size() != after.Size() || int64(len(content)) != opened.Size() || !trustedFile(path, after) || !ancestors.stillTrusted(path) {
		return nil, invalid()
	}
	return content, nil
}

func validateKnownHosts(path string) error {
	if !validKnownHostsPath(path) {
		return invalid()
	}
	ancestors, ok := snapshotTrustedAncestors(path)
	if !ok {
		return invalid()
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() < 1 || before.Size() > maximumKnownHostsSize || !trustedFile(path, before) {
		return invalid()
	}
	file, err := os.Open(path)
	if err != nil {
		return invalid()
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || !trustedFile(path, opened) {
		return invalid()
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, after) || opened.Size() != after.Size() || !trustedFile(path, after) || !ancestors.stillTrusted(path) {
		return invalid()
	}
	return nil
}

func validExecutablePath(path string) bool {
	if !validConfiguredPath(path) {
		return false
	}
	base := strings.ToLower(filepath.Base(path))
	return base == "ssh" || base == "ssh.exe"
}

func validateExecutable(path string) error {
	ancestors, ok := snapshotTrustedAncestors(path)
	if !ok {
		return invalid()
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() < 1 || before.Size() > maximumExecutableSize || !trustedExecutable(path, before) {
		return invalid()
	}
	file, err := os.Open(path)
	if err != nil {
		return invalid()
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || !trustedExecutable(path, opened) {
		return invalid()
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, after) || opened.Size() != after.Size() || !trustedExecutable(path, after) || !ancestors.stillTrusted(path) {
		return invalid()
	}
	return nil
}

func constrainedSSHArguments(knownHosts, destination string) []string {
	return []string{
		"-F", "none", "-T",
		"-o", "AddKeysToAgent=no",
		"-o", "BatchMode=yes",
		"-o", "CanonicalizeHostname=no",
		"-o", "CheckHostIP=yes",
		"-o", "ClearAllForwardings=yes",
		"-o", "ControlMaster=no",
		"-o", "EscapeChar=none",
		"-o", "ExitOnForwardFailure=yes",
		"-o", "ForwardAgent=no",
		"-o", "ForwardX11=no",
		"-o", "GatewayPorts=no",
		"-o", "GlobalKnownHostsFile=none",
		"-o", "HostbasedAuthentication=no",
		"-o", "IdentityAgent=none",
		"-o", "IdentitiesOnly=yes",
		"-o", "KbdInteractiveAuthentication=no",
		"-o", "PasswordAuthentication=no",
		"-o", "PermitLocalCommand=no",
		"-o", "ProxyCommand=none",
		"-o", "ProxyJump=none",
		"-o", "RemoteCommand=none",
		"-o", "RequestTTY=no",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UpdateHostKeys=no",
		"-o", "UserKnownHostsFile=" + knownHosts,
		"-o", "VerifyHostKeyDNS=no",
		destination,
	}
}

func invalid() error { return failure.New(generated.ErrorCodeInputInvalid, "client-profile", false) }

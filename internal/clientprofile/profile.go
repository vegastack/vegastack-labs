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
	"runtime"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

const maximumProfileBytes = 64 * 1024

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
}

// Load returns matched=false when path is not a client profile, allowing the
// existing protected server-profile loader to remain the local path owner.
func Load(ctx context.Context, path string) (serverconfig.Profile, bool, error) {
	if ctx == nil || ctx.Err() != nil {
		return serverconfig.Profile{}, true, failure.New(generated.ErrorCodeInterrupted, "client-profile", false)
	}
	if path == "" || strings.ContainsRune(path, 0) || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return serverconfig.Profile{}, true, invalid()
	}
	before, err := os.Lstat(path)
	if err != nil {
		return serverconfig.Profile{}, false, nil
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || (runtime.GOOS != "windows" && before.Mode().Perm()&0o077 != 0) || before.Size() < 1 || before.Size() > maximumProfileBytes {
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
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var profile document
	if decoder.Decode(&profile) != nil {
		return serverconfig.Profile{}, true, invalid()
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF || profile.SchemaVersion != "1.0.0" || profile.Transport.Kind != "constrained-ssh" ||
		(profile.Transport.Executable != "ssh" && profile.Transport.Executable != "ssh.exe") ||
		!destinationPattern.MatchString(profile.Transport.Destination) || len(profile.Transport.Destination) > 255 ||
		len(profile.Transport.KnownHostsPath) > 4096 || strings.ContainsRune(profile.Transport.KnownHostsPath, 0) ||
		!filepath.IsAbs(profile.Transport.KnownHostsPath) || filepath.Clean(profile.Transport.KnownHostsPath) != profile.Transport.KnownHostsPath {
		return serverconfig.Profile{}, true, invalid()
	}
	arguments := []string{
		"-T", "-o", "BatchMode=yes", "-o", "ClearAllForwardings=yes", "-o", "ExitOnForwardFailure=yes",
		"-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + profile.Transport.KnownHostsPath,
		profile.Transport.Destination,
	}
	return serverconfig.Profile{ConstrainedSSH: &serverconfig.ConstrainedSSH{Executable: profile.Transport.Executable, Arguments: arguments}}, true, nil
}

func invalid() error { return failure.New(generated.ErrorCodeInputInvalid, "client-profile", false) }

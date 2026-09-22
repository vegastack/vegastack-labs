//go:build linux

package backup

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strconv"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
)

// RetentionResticRequest is a separate destructive capability. Successful
// process exit is only a process observation; the caller must reconcile the
// complete snapshot/object inventory and prove every survivor independently.
type RetentionResticRequest struct {
	BinaryPath, RepositoryURL, Mode string
	SnapshotIDs                     []string
	MaxRepackBytes                  int64
}

func RunRetentionRestic(ctx context.Context, request RetentionResticRequest, password *credentialref.Value) (ResticObservation, error) {
	var observed ResticObservation
	if ctx == nil || ctx.Err() != nil || password == nil || len(password.Bytes()) == 0 || request.BinaryPath == "" || request.RepositoryURL == "" {
		return observed, errors.New("retention restic request invalid")
	}
	if request.Mode != "forget-dry-run" && request.Mode != "forget" && request.Mode != "prune" {
		return observed, errors.New("retention restic mode invalid")
	}
	if request.Mode == "prune" {
		if len(request.SnapshotIDs) != 0 || request.MaxRepackBytes < 0 || request.MaxRepackBytes > maxObjectBytes {
			return observed, errors.New("retention prune bounds invalid")
		}
	} else {
		if len(request.SnapshotIDs) < 1 || len(request.SnapshotIDs) > 256 {
			return observed, errors.New("retention exact snapshot set invalid")
		}
		seen := make(map[string]bool, len(request.SnapshotIDs))
		for _, id := range request.SnapshotIDs {
			if !validObjectName(id) || seen[id] {
				return observed, errors.New("retention snapshot id invalid")
			}
			seen[id] = true
		}
	}
	runner := &resticRunner{}
	binaryFile, err := runner.verifyBinary(ResticRequest{BinaryPath: request.BinaryPath, Architecture: runtime.GOARCH})
	if err != nil {
		return observed, errors.New("retention restic binary untrusted")
	}
	defer binaryFile.Close()
	passwordFile, err := sealedPasswordFile(password.Bytes())
	if err != nil {
		return observed, errors.New("retention password unavailable")
	}
	defer passwordFile.Close()
	argv := []string{request.BinaryPath, "-r", "rest:" + request.RepositoryURL, "--no-cache", "--password-file", passwordFilePath}
	if request.Mode == "prune" {
		argv = append(argv, "prune", "--max-unused", "unlimited", "--max-repack-size", strconv.FormatInt(request.MaxRepackBytes, 10))
	} else {
		argv = append(argv, "forget")
		if request.Mode == "forget-dry-run" {
			argv = append(argv, "--dry-run")
		}
		argv = append(argv, request.SnapshotIDs...)
	}
	command := exec.CommandContext(ctx, argv[0], argv[1:]...)
	command.Path = "/proc/self/fd/4"
	command.ExtraFiles = []*os.File{passwordFile, binaryFile}
	command.Env = []string{}
	var stdout, stderr bytes.Buffer
	stdoutWriter := &boundedWriter{limit: 4 << 20, buffer: &stdout}
	stderrWriter := &boundedWriter{limit: 4 << 20, buffer: &stderr}
	command.Stdout, command.Stderr = stdoutWriter, stderrWriter
	observed = ResticObservation{Argv: append([]string(nil), argv...), Env: append([]string(nil), command.Env...), PasswordFileMode: "sealed-memfd"}
	if err := command.Run(); err != nil || stdoutWriter.exceeded || stderrWriter.exceeded || ctx.Err() != nil {
		return observed, errors.New("retention restic process failed")
	}
	// Text/exit status is intentionally not exposed as an authority signal.
	return observed, nil
}

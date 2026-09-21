//go:build linux

package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"golang.org/x/sys/unix"
)

const (
	defaultResticOutputLimit = 1 << 20 // 1 MiB of bounded child output
	maxResticBinaryBytes     = 128 * 1024 * 1024
	passwordChildFD          = 3
	passwordFilePath         = "/proc/self/fd/3"
)

// resticRunner runs the pinned restic child with a sealed anonymous memory
// password FD. expectedDigest overrides the architecture-derived pinned digest
// for isolated tests that exercise the exact same sealing and no-leak path
// against a verified fake binary.
type resticRunner struct {
	expectedDigest string
	clock          func() time.Time
	observation    ResticObservation
	// afterVerify is used only by the Linux path-swap test. Production leaves it nil.
	afterVerify func()
}

// NewResticRunner builds the production pinned restic runner.
func NewResticRunner() ResticRunner { return &resticRunner{clock: time.Now} }

// NewResticRunnerForTest builds a runner that verifies against an explicit binary
// digest instead of the architecture-pinned one. It exercises the identical
// sealing and no-leak path; it never relaxes any secret-handling guard.
func NewResticRunnerForTest(expectedDigest string, clock func() time.Time) ResticRunner {
	if clock == nil {
		clock = time.Now
	}
	return &resticRunner{expectedDigest: expectedDigest, clock: clock}
}

func (runner *resticRunner) Observation() ResticObservation { return runner.observation }

// resticSummary is the subset of restic's `backup --json` summary message the
// runner consumes. Only stable, non-secret fields are read.
type resticSummary struct {
	MessageType         string `json:"message_type"`
	SnapshotID          string `json:"snapshot_id"`
	TotalFilesProcessed int64  `json:"total_files_processed"`
	TotalBytesProcessed int64  `json:"total_bytes_processed"`
}

func (runner *resticRunner) Run(ctx context.Context, request ResticRequest, password *credentialref.Value) (result ResticResult, outcomeErr error) {
	runner.observation = ResticObservation{PasswordFileMode: "sealed-memfd"}
	if password == nil || len(password.Bytes()) == 0 || request.BinaryPath == "" || request.RepositoryURL == "" {
		return ResticResult{}, failure.New(generated.ErrorCodeInputInvalid, "backup-restic", false)
	}
	outputLimit := request.OutputLimit
	if outputLimit <= 0 {
		outputLimit = defaultResticOutputLimit
	}
	binaryFile, err := runner.verifyBinary(request)
	if err != nil {
		return ResticResult{}, failure.New(generated.ErrorCodeIntegrityFailure, "backup-restic-binary", false)
	}
	// The verified inode stays open and is executed via /proc/self/fd so the child
	// runs exactly the hashed binary, not a path re-resolved after the check.
	defer binaryFile.Close()
	if runner.afterVerify != nil {
		runner.afterVerify()
	}

	mode := request.Mode
	if mode == "" {
		mode = "backup"
	}
	if mode != "backup" && mode != "init" && mode != "config" {
		return ResticResult{}, failure.New(generated.ErrorCodeInputInvalid, "backup-restic", false)
	}
	if mode == "backup" && request.SnapshotPath == "" {
		return ResticResult{}, failure.New(generated.ErrorCodeInputInvalid, "backup-restic", false)
	}

	passwordFile, err := sealedPasswordFile(password.Bytes())
	if err != nil {
		return ResticResult{}, failure.New(generated.ErrorCodeIntegrityFailure, "backup-restic-password", false)
	}
	// The sealed memfd is closed on every exit path; the kernel frees the only
	// copy of the password material with it.
	defer passwordFile.Close()

	argv := []string{
		request.BinaryPath,
		"-r", "rest:" + request.RepositoryURL,
		"--json", "--no-cache",
		"--password-file", passwordFilePath,
	}
	if mode == "init" {
		argv = append(argv, "init", "--repository-version", "2")
	} else if mode == "config" {
		argv = append(argv, "cat", "config")
	} else {
		argv = append(argv, "backup", request.SnapshotPath, "--host", "vsk-labs")
	}
	command := exec.CommandContext(ctx, argv[0], argv[1:]...)
	command.Env = []string{} // empty environment: the password never travels via any env variable or a helper command
	// Password is the child's fd 3; the verified binary is fd 4. Executing
	// /proc/self/fd/4 binds exec to the exact verified inode.
	command.ExtraFiles = []*os.File{passwordFile, binaryFile}
	command.Path = "/proc/self/fd/4"
	var stdout, stderr bytes.Buffer
	command.Stdout = &boundedWriter{limit: outputLimit, buffer: &stdout}
	command.Stderr = &boundedWriter{limit: outputLimit, buffer: &stderr}

	runner.observation.Argv = append([]string(nil), argv...)
	runner.observation.Env = append([]string(nil), command.Env...)

	started := runner.clock().UTC()
	runErr := command.Run()
	completed := runner.clock().UTC()
	if mode != "config" {
		runner.observation.Stdout = stdout.String()
	}
	runner.observation.Stderr = stderr.String()
	if runErr != nil {
		if ctx.Err() != nil {
			return ResticResult{}, failure.New(generated.ErrorCodeInterrupted, "backup-restic", false)
		}
		return ResticResult{}, failure.New(generated.ErrorCodeExecutionFailed, "backup-restic", false)
	}

	if mode == "init" {
		return ResticResult{RepositoryFormat: 2, StartedAt: started, CompletedAt: completed}, nil
	}
	if mode == "config" {
		var config struct {
			Version int    `json:"version"`
			ID      string `json:"id"`
		}
		decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
		if err := decoder.Decode(&config); err != nil || config.Version != 2 {
			return ResticResult{}, failure.New(generated.ErrorCodeIntegrityFailure, "backup-restic-config", false)
		}
		id, idErr := hex.DecodeString(config.ID)
		if idErr != nil || len(id) != 32 {
			return ResticResult{}, failure.New(generated.ErrorCodeIntegrityFailure, "backup-restic-config", false)
		}
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			return ResticResult{}, failure.New(generated.ErrorCodeIntegrityFailure, "backup-restic-config", false)
		}
		return ResticResult{RepositoryFormat: config.Version, StartedAt: started, CompletedAt: completed}, nil
	}

	summary, err := parseResticSummary(stdout.Bytes())
	if err != nil || summary.SnapshotID == "" || summary.TotalFilesProcessed <= 0 {
		return ResticResult{}, failure.New(generated.ErrorCodeIntegrityFailure, "backup-restic-output", false)
	}
	return ResticResult{
		SnapshotID:       summary.SnapshotID,
		SnapshotCount:    1,
		ObjectCount:      summary.TotalFilesProcessed,
		ObjectBytes:      summary.TotalBytesProcessed,
		RepositoryFormat: 2,
		StartedAt:        started,
		CompletedAt:      completed,
	}, nil
}

// verifyBinary confirms the restic executable is a service-owned regular file
// that is not group/other writable and whose SHA-256 matches the exact pinned
// (or test-pinned) digest, without executing it first.
func (runner *resticRunner) verifyBinary(request ResticRequest) (*os.File, error) {
	expected := runner.expectedDigest
	if expected == "" {
		digest, ok := serverconfig.ExpectedResticExecutableDigest(request.Architecture)
		if !ok {
			return nil, errors.New("unsupported architecture")
		}
		expected = digest
	}
	descriptor, err := unix.Openat2(unix.AT_FDCWD, request.BinaryPath, &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW),
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), "restic-binary")
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, errors.New("descriptor unavailable")
	}
	var stat unix.Stat_t
	if unix.Fstat(descriptor, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 ||
		stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o022 != 0 || stat.Mode&0o100 == 0 ||
		stat.Size <= 0 || stat.Size > maxResticBinaryBytes {
		_ = file.Close()
		return nil, errors.New("unsafe restic binary")
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		_ = file.Close()
		return nil, err
	}
	if hex.EncodeToString(hasher.Sum(nil)) != expected {
		_ = file.Close()
		return nil, errors.New("restic binary digest mismatch")
	}
	// Return the still-open verified descriptor so the child executes exactly this
	// inode (via /proc/self/fd) rather than re-resolving the path, closing the
	// check-then-exec window.
	return file, nil
}

// sealedPasswordFile creates an anonymous memory file, writes the borrowed
// password bytes once, seals it fully read-only, and rewinds it. The returned
// file is the only reference; closing it frees the kernel copy.
func sealedPasswordFile(password []byte) (*os.File, error) {
	descriptor, err := unix.MemfdCreate("vsk-restic-password", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), "restic-password")
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, errors.New("memfd unavailable")
	}
	written, err := file.Write(password)
	if err != nil || written != len(password) {
		_ = file.Close()
		return nil, errors.New("password write failed")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return nil, err
	}
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_SHRINK|unix.F_SEAL_GROW|unix.F_SEAL_SEAL); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func parseResticSummary(output []byte) (resticSummary, error) {
	decoder := json.NewDecoder(bytes.NewReader(output))
	var summary resticSummary
	for {
		var message resticSummary
		if err := decoder.Decode(&message); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			// restic emits a stream of heterogeneous JSON objects; skip any that
			// do not decode into the summary shape without failing the whole parse.
			var discard json.RawMessage
			if decoder.Decode(&discard) != nil {
				break
			}
			continue
		}
		if message.MessageType == "summary" {
			summary = message
		}
	}
	if summary.MessageType != "summary" {
		return resticSummary{}, errors.New("no restic summary")
	}
	return summary, nil
}

// boundedWriter caps captured child output and never records more than its limit,
// keeping any inadvertently large or hostile output from exhausting memory.
type boundedWriter struct {
	limit   int64
	written int64
	buffer  *bytes.Buffer
}

func (writer *boundedWriter) Write(data []byte) (int, error) {
	if writer.written >= writer.limit {
		return len(data), nil
	}
	remaining := writer.limit - writer.written
	if int64(len(data)) > remaining {
		writer.buffer.Write(data[:remaining])
		writer.written = writer.limit
		return len(data), nil
	}
	writer.buffer.Write(data)
	writer.written += int64(len(data))
	return len(data), nil
}

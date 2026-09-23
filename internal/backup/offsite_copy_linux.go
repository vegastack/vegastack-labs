//go:build linux

package backup

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"syscall"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"golang.org/x/sys/unix"
)

const (
	offsitePasswordPath = "/proc/self/fd/3"
	offsiteBearerPath   = "/proc/self/fd/4"
)

// runBrokeredOffsiteRestic is the only production route from the controller to
// direct S3 restic. The root broker rechecks the exact writer lease before each
// child, executes the already verified inode, and gives the child only two
// sealed secret descriptors.
func runBrokeredOffsiteRestic(ctx context.Context, policy CustodyPolicy, session CustodySession, verifier LeaseVerifier, request OffsiteResticRequest, passwordFile, bearerFile *os.File) (OffsiteResticResult, error) {
	if verifier == nil || session.Role != "offsite-writer" || session.WriterLease == nil ||
		request.BinaryPath != policy.ResticBinaryPath || request.Architecture != runtime.GOARCH ||
		request.RepositoryURL != session.OffsiteRepositoryURL || !validOffsiteRepositoryURL(request.RepositoryURL) ||
		request.RunID != session.RunID || request.StepID != session.StepID || request.PointID != session.PointID ||
		request.GenerationID != session.GenerationID || request.RecoveryEpoch != session.RecoveryEpoch ||
		request.PasswordFDPath != offsitePasswordPath || request.AuthorizationTokenFDPath != offsiteBearerPath ||
		!validLoopbackIAMURI(request.IAMURI, OneRunIAMPath(adapterSessionFromCustody(session))) ||
		!exactSealedPasswordFile(passwordFile) || !exactSealedBearerFile(bearerFile) {
		return OffsiteResticResult{}, errors.New("offsite restic request outside custody policy")
	}
	wantArgs := []string{request.BinaryPath, "-r", request.RepositoryURL, "--json", "--no-cache", "--password-file", offsitePasswordPath, "backup", request.SnapshotPath, "--host", "vsk-labs"}
	wantEnv := []string{"HOME=/nonexistent", "RESTIC_PASSWORD_FILE=" + offsitePasswordPath, "AWS_CONTAINER_CREDENTIALS_FULL_URI=" + request.IAMURI, "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE=" + offsiteBearerPath}
	if !equalStrings(request.Arguments, wantArgs) || !equalStrings(request.Environment, wantEnv) {
		return OffsiteResticResult{}, errors.New("offsite restic process contract changed")
	}
	transfer, err := prepareBackupExchange(policy, request.SnapshotPath)
	if err != nil {
		return OffsiteResticResult{}, err
	}
	defer transfer.Close()

	runner := &resticRunner{}
	binaryFile, err := runner.verifyBinary(ResticRequest{BinaryPath: request.BinaryPath, Architecture: request.Architecture})
	if err != nil {
		return OffsiteResticResult{}, err
	}
	defer binaryFile.Close()
	run := func(arguments []string, capture bool) ([]byte, error) {
		if err := verifier.VerifyWriterLease(*session.WriterLease, nowOr(nil)); err != nil {
			return nil, errors.New("offsite writer lease expired")
		}
		for _, file := range []*os.File{passwordFile, bearerFile, binaryFile} {
			if _, err := file.Seek(0, io.SeekStart); err != nil {
				return nil, err
			}
		}
		command := exec.CommandContext(ctx, "/proc/self/fd/5", arguments...)
		command.Args[0] = request.BinaryPath
		command.ExtraFiles = []*os.File{passwordFile, bearerFile, binaryFile}
		command.Env = wantEnv
		command.Stdin = bytes.NewReader(nil)
		command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: policy.ResticUID, Gid: policy.ResticUID}}
		var stdout, stderr bytes.Buffer
		stdoutWriter := &boundedWriter{limit: defaultResticOutputLimit, buffer: &stdout}
		stderrWriter := &boundedWriter{limit: defaultResticOutputLimit, buffer: &stderr}
		command.Stdout, command.Stderr = stdoutWriter, stderrWriter
		if err := command.Run(); err != nil || stdoutWriter.exceeded || stderrWriter.exceeded {
			return nil, errors.New("offsite restic child failed")
		}
		if capture {
			return stdout.Bytes(), nil
		}
		return nil, nil
	}
	common := []string{"-r", request.RepositoryURL, "--json", "--no-cache", "--password-file", offsitePasswordPath}
	if _, err := run(append(append([]string{}, common...), "init", "--repository-version", "2"), false); err != nil {
		return OffsiteResticResult{}, errors.Join(err, transfer.ReturnOwnership())
	}
	backupOutput, err := run(append(append([]string{}, common...), "backup", request.SnapshotPath, "--host", "vsk-labs"), true)
	if err != nil {
		return OffsiteResticResult{}, errors.Join(err, transfer.ReturnOwnership())
	}
	summary, err := parseResticSummary(backupOutput)
	if err != nil || !validObjectName(summary.SnapshotID) || summary.TotalFilesProcessed < 1 || summary.TotalBytesProcessed < 1 {
		return OffsiteResticResult{}, errors.Join(errors.New("invalid offsite restic summary"), transfer.ReturnOwnership())
	}
	configOutput, err := run(append(append([]string{}, common...), "cat", "config"), true)
	if err != nil {
		return OffsiteResticResult{}, errors.Join(err, transfer.ReturnOwnership())
	}
	repositoryID, err := parseOffsiteRepositoryID(configOutput)
	return OffsiteResticResult{RepositoryID: repositoryID, SnapshotID: summary.SnapshotID, ObjectCount: summary.TotalFilesProcessed, ObjectBytes: summary.TotalBytesProcessed, ChildExited: err == nil}, errors.Join(err, transfer.ReturnOwnership())
}

func adapterSessionFromCustody(session CustodySession) adapter.SessionRequest {
	return adapter.SessionRequest{RunID: session.RunID, StepID: session.StepID, PointID: session.PointID, GenerationID: session.GenerationID, RecoveryEpoch: session.RecoveryEpoch}
}

func parseOffsiteRepositoryID(output []byte) (string, error) {
	var config struct {
		Version int    `json:"version"`
		ID      string `json:"id"`
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	if decoder.Decode(&config) != nil || config.Version != 2 || len(config.ID) != 64 {
		return "", errors.New("invalid offsite repository config")
	}
	decoded, err := hex.DecodeString(config.ID)
	var extra any
	if err != nil || len(decoded) != 32 || !errors.Is(decoder.Decode(&extra), io.EOF) {
		return "", errors.New("invalid offsite repository config")
	}
	return config.ID, nil
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func exactSealedBearerFile(file *os.File) bool {
	if file == nil {
		return false
	}
	var stat unix.Stat_t
	seals, err := unix.FcntlInt(file.Fd(), unix.F_GET_SEALS, 0)
	want := unix.F_SEAL_WRITE | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_SEAL
	if err != nil || seals != want || unix.Fstat(int(file.Fd()), &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Size < 32 || stat.Size > 1<<20 {
		return false
	}
	_, err = file.Seek(0, io.SeekStart)
	return err == nil
}

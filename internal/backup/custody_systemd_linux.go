//go:build linux

package backup

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"golang.org/x/sys/unix"
)

const (
	CustodyPolicyPath       = "/etc/vsk-labs/backup-custody.json"
	CustodySystemdMode      = "__backup-custody-supervisor"
	CustodyPolicyCheckMode  = "__backup-custody-policy-check"
	maxCustodyPolicyRequest = 512
)

var custodyInstancePattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

type systemdCustodyClient struct {
	session     CustodySession
	nonce       string
	command     *os.File
	verify      *os.File
	journal     CustodyJournal
	socketPaths []string
	mu          sync.Mutex
	observation ResticObservation
}

type resticCustodyResponse struct {
	Result      ResticResult      `json:"result"`
	Observation ResticObservation `json:"observation"`
}

func (launcher CustodyLauncher) startSystemd(ctx context.Context, policy CustodyPolicy, session CustodySession) (CustodyClient, error) {
	if launcher.PolicyPath != CustodyPolicyPath || launcher.Journal == nil ||
		(session.Role == "writer" && launcher.Writer == nil) || (session.Role == "verifier" && launcher.Reader == nil) || (session.Role == "retention" && (launcher.Retention == nil || launcher.Mutations == nil)) {
		return nil, errors.New("custody launch rejected")
	}
	nonce := make([]byte, 32)
	instanceBytes := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	if _, err := rand.Read(instanceBytes); err != nil {
		return nil, err
	}
	session.NonceDigest = custodyNonceDigest(nonce)
	if !session.valid(nowOr(launcher.Clock), policy.MaximumLifetime) {
		return nil, errors.New("custody session invalid")
	}
	if err := launcher.Journal.BeginCustody(ctx, session); err != nil {
		return nil, err
	}
	failed := true
	defer func() {
		if failed {
			_ = launcher.Journal.FinishCustody(context.WithoutCancel(ctx), session, "uncertain")
		}
	}()
	instance := hex.EncodeToString(instanceBytes)
	commandPath := filepath.Join(policy.RequestRoot, instance+".command.sock")
	verifyPath := filepath.Join(policy.RequestRoot, instance+".verify.sock")
	commandListener, err := custodyListener(commandPath)
	if err != nil {
		return nil, err
	}
	defer commandListener.Close()
	verifyListener, err := custodyListener(verifyPath)
	if err != nil {
		_ = os.Remove(commandPath)
		return nil, err
	}
	defer verifyListener.Close()
	defer func() {
		if failed {
			_ = os.Remove(commandPath)
			_ = os.Remove(verifyPath)
		}
	}()
	if err := startCustodyUnit(ctx, policy, instance); err != nil {
		return nil, err
	}
	acceptCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	commandConn, err := acceptCustodyConnection(acceptCtx, commandListener, 0)
	if err != nil {
		return nil, fmt.Errorf("custody command accept: %w", err)
	}
	verifyConn, err := acceptCustodyConnection(acceptCtx, verifyListener, 0)
	if err != nil {
		_ = commandConn.Close()
		return nil, fmt.Errorf("custody verify accept: %w", err)
	}
	commandFile, err := commandConn.File()
	_ = commandConn.Close()
	if err != nil {
		_ = verifyConn.Close()
		return nil, err
	}
	verifyFile, err := verifyConn.File()
	_ = verifyConn.Close()
	if err != nil {
		_ = commandFile.Close()
		return nil, err
	}
	launch := custodyLaunch{Session: session, Nonce: hex.EncodeToString(nonce)}
	launchPayload, err := json.Marshal(launch)
	if err != nil || writeCustodyFrame(commandFile, custodyFrame{Type: "launch", NonceDigest: session.NonceDigest, Payload: launchPayload}) != nil {
		_ = commandFile.Close()
		_ = verifyFile.Close()
		return nil, errors.New("custody launch transmission failed")
	}
	client := &systemdCustodyClient{session: session, nonce: session.NonceDigest, command: commandFile, verify: verifyFile,
		journal: launcher.Journal, socketPaths: []string{commandPath, verifyPath}}
	go serveSystemdVerification(client, launcher.Writer, launcher.Reader, launcher.Retention, launcher.Mutations)
	readyCtx, readyCancel := context.WithTimeout(ctx, 30*time.Second)
	defer readyCancel()
	if _, err := client.request(readyCtx, "ready", nil); err != nil {
		_ = commandFile.Close()
		_ = verifyFile.Close()
		return nil, fmt.Errorf("custody supervisor ready: %w", err)
	}
	failed = false
	return client, nil
}

func custodyListener(path string) (*net.UnixListener, error) {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		return nil, err
	}
	return listener, nil
}

func startCustodyUnit(ctx context.Context, policy CustodyPolicy, instance string) error {
	if !custodyInstancePattern.MatchString(instance) {
		return errors.New("custody unit rejected")
	}
	unit := strings.Replace(policy.UnitTemplate, "@.service", "@"+instance+".service", 1)
	subject, err := currentCustodyPolicySubject(policy.ControllerUID)
	if err != nil || !effectiveCustodyStartPolicy(ctx, policy, unit, subject, runCustodyPolicyCommand, readCustodySudoAggregate, requestRootCustodyPolicyCheck) {
		return errors.New("custody authority policy rejected")
	}
	file, err := openRootExecutable("/usr/bin/systemctl")
	if err != nil {
		return err
	}
	defer file.Close()
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	command := exec.CommandContext(bounded, "/proc/self/fd/3", "--system", "--no-ask-password", "start", unit)
	command.Args[0] = "/usr/bin/systemctl"
	command.ExtraFiles = []*os.File{file}
	command.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin"}
	command.Stdin = strings.NewReader("")
	command.Stdout, command.Stderr = io.Discard, io.Discard
	if command.Run() != nil || bounded.Err() != nil {
		return errors.New("custody unit start rejected")
	}
	return nil
}

type custodyPolicyRunner func(context.Context, string, []string) int
type custodySudoReader func(context.Context) ([]byte, error)
type custodyRootPolicyCheck func(context.Context, CustodyPolicy, string, string) bool

type custodyPolicyCheckRequest struct {
	UnitName string `json:"unit_name"`
	Subject  string `json:"subject"`
}

func currentCustodyPolicySubject(expectedUID uint32) (string, error) {
	uid := os.Getuid()
	if uid == 0 || uid != os.Geteuid() || uint32(uid) != expectedUID {
		return "", errors.New("custody policy subject rejected")
	}
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return "", err
	}
	end := bytes.LastIndexByte(data, ')')
	if end < 0 || end+2 >= len(data) {
		return "", errors.New("custody policy subject invalid")
	}
	fields := strings.Fields(string(data[end+2:]))
	if len(fields) <= 19 {
		return "", errors.New("custody policy subject invalid")
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || start == 0 {
		return "", errors.New("custody policy subject invalid")
	}
	return fmt.Sprintf("%d,%d,%d", os.Getpid(), start, uid), nil
}

// effectiveCustodyStartPolicy mirrors the #143 local-authority qualification:
// the exact action must be allowed while adjacent verbs, units and broader
// systemd administration remain denied for the live controller subject.
func effectiveCustodyStartPolicy(ctx context.Context, policy CustodyPolicy, unit, subject string, run custodyPolicyRunner, aggregate custodySudoReader, rootCheck custodyRootPolicyCheck) bool {
	if ctx == nil || ctx.Err() != nil || run == nil || aggregate == nil || rootCheck == nil || subject == "" ||
		!regexp.MustCompile(`^vsk-labs-backup-custody@[a-f0-9]{32}\.service$`).MatchString(unit) {
		return false
	}
	checks := []struct {
		args []string
		want int
	}{
		{[]string{"-n", "-l", "--", policy.ExecutablePath, CustodyPolicyCheckMode}, 0},
		{[]string{"-n", "-l", "--", policy.ExecutablePath, CustodyPolicyCheckMode, "extra"}, 1},
		{[]string{"-n", "-l", "--", policy.ExecutablePath, CustodySystemdMode, strings.Repeat("a", 32)}, 1},
		{[]string{"-n", "-l", "--", "/usr/bin/systemctl", "--version"}, 1},
		{[]string{"-n", "-l", "--", "/usr/bin/true"}, 1},
	}
	for _, check := range checks {
		if run(ctx, "/usr/bin/sudo", check.args) != check.want {
			return false
		}
	}
	listing, err := aggregate(ctx)
	return err == nil && exactCustodySudoAggregate(listing, policy.ExecutablePath) && rootCheck(ctx, policy, unit, subject)
}

func exactCustodySudoAggregate(data []byte, executable string) bool {
	if len(data) == 0 || len(data) > 4096 || !bytes.HasSuffix(data, []byte("\n")) {
		return false
	}
	listing := string(data)
	const header = "\nUser vsk-controller may run the following commands on "
	before, commands, found := strings.Cut(listing, header)
	if !found || strings.Contains(before, "User vsk-controller may run") || strings.Count(commands, "\n") != 2 {
		return false
	}
	line := commands[strings.IndexByte(commands, '\n')+1:]
	return line == "    (root) NOPASSWD: "+executable+" "+CustodyPolicyCheckMode+"\n"
}

func readCustodySudoAggregate(ctx context.Context) ([]byte, error) {
	trusted, err := openRootExecutable("/usr/bin/sudo")
	if err != nil {
		return nil, err
	}
	defer trusted.Close()
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	command := exec.CommandContext(bounded, "/proc/self/fd/3", "-n", "-l")
	command.Args[0] = "/usr/bin/sudo"
	command.ExtraFiles = []*os.File{trusted}
	command.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin"}
	command.Stdin = strings.NewReader("")
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if command.Run() != nil || bounded.Err() != nil || stderr.Len() != 0 || stdout.Len() > 4096 {
		return nil, errors.New("custody sudo policy rejected")
	}
	return stdout.Bytes(), nil
}

func requestRootCustodyPolicyCheck(ctx context.Context, policy CustodyPolicy, unit, subject string) bool {
	payload, err := json.Marshal(custodyPolicyCheckRequest{UnitName: unit, Subject: subject})
	if err != nil || len(payload) > maxCustodyPolicyRequest {
		return false
	}
	trusted, err := openRootExecutable("/usr/bin/sudo")
	if err != nil {
		return false
	}
	defer trusted.Close()
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	command := exec.CommandContext(bounded, "/proc/self/fd/3", "-n", "--", policy.ExecutablePath, CustodyPolicyCheckMode)
	command.Args[0] = "/usr/bin/sudo"
	command.ExtraFiles = []*os.File{trusted}
	command.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin"}
	command.Stdin = bytes.NewReader(payload)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	return command.Run() == nil && bounded.Err() == nil && stdout.Len() == 0 && stderr.Len() == 0
}

func exactLiveCustodyPolicySubject(subject, sudoUID string) bool {
	parts := strings.Split(subject, ",")
	if len(parts) != 3 || parts[2] != sudoUID {
		return false
	}
	pid, err := strconv.Atoi(parts[0])
	if err != nil || pid <= 1 {
		return false
	}
	start, err := strconv.ParseUint(parts[1], 10, 64)
	uid, uidErr := strconv.ParseUint(parts[2], 10, 32)
	if err != nil || start == 0 || uidErr != nil || uid == 0 {
		return false
	}
	stat, err := os.ReadFile("/proc/" + parts[0] + "/stat")
	if err != nil {
		return false
	}
	end := bytes.LastIndexByte(stat, ')')
	fields := []string(nil)
	if end >= 0 && end+2 < len(stat) {
		fields = strings.Fields(string(stat[end+2:]))
	}
	if len(fields) <= 19 || fields[19] != parts[1] {
		return false
	}
	status, err := os.ReadFile("/proc/" + parts[0] + "/status")
	if err != nil {
		return false
	}
	found := false
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			ids := strings.Fields(strings.TrimPrefix(line, "Uid:"))
			if len(ids) != 4 {
				return false
			}
			for _, id := range ids {
				if id != parts[2] {
					return false
				}
			}
			found = true
		}
	}
	return found
}

// RunCustodyPolicyCheck is the exact-argv root helper admitted by sudoers. It
// performs read-only polkit queries for one live controller process and never
// starts a unit or accepts a caller-selected path.
func RunCustodyPolicyCheck(ctx context.Context, input io.Reader) int {
	if ctx == nil || ctx.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 {
		return 2
	}
	policy, err := LoadCustodyPolicy(CustodyPolicyPath)
	if err != nil || os.Getenv("SUDO_UID") != strconv.FormatUint(uint64(policy.ControllerUID), 10) {
		return 2
	}
	data, err := io.ReadAll(io.LimitReader(input, maxCustodyPolicyRequest+1))
	if err != nil || len(data) == 0 || len(data) > maxCustodyPolicyRequest {
		return 2
	}
	var request custodyPolicyCheckRequest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF ||
		!regexp.MustCompile(`^vsk-labs-backup-custody@[a-f0-9]{32}\.service$`).MatchString(request.UnitName) ||
		!exactLiveCustodyPolicySubject(request.Subject, os.Getenv("SUDO_UID")) {
		return 2
	}
	pk := func(action string, details ...string) []string {
		args := []string{"--action-id", action, "--process", request.Subject}
		return append(args, details...)
	}
	manage := "org.freedesktop.systemd1.manage-units"
	checks := []struct {
		args []string
		want int
	}{
		{pk(manage, "--detail", "verb", "start", "--detail", "unit", request.UnitName), 0},
		{pk(manage, "--detail", "verb", "stop", "--detail", "unit", request.UnitName), 1},
		{pk(manage, "--detail", "verb", "restart", "--detail", "unit", request.UnitName), 1},
		{pk(manage, "--detail", "verb", "start", "--detail", "unit", "vsk-authority-denied.service"), 1},
		{pk(manage), 1},
		{pk("org.freedesktop.systemd1.manage-unit-files"), 1},
		{pk("org.freedesktop.systemd1.reload-daemon"), 1},
	}
	for _, check := range checks {
		if runCustodyPolicyCommand(ctx, "/usr/bin/pkcheck", check.args) != check.want {
			return 2
		}
	}
	if !exactLiveCustodyPolicySubject(request.Subject, os.Getenv("SUDO_UID")) {
		return 2
	}
	return 0
}

func runCustodyPolicyCommand(ctx context.Context, path string, args []string) int {
	trusted, err := openRootExecutable(path)
	if err != nil {
		return -1
	}
	defer trusted.Close()
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	command := exec.CommandContext(bounded, "/proc/self/fd/3", args...)
	command.Args[0] = path
	command.ExtraFiles = []*os.File{trusted}
	command.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin"}
	command.Stdin = strings.NewReader("")
	command.Stdout, command.Stderr = io.Discard, io.Discard
	err = command.Run()
	if bounded.Err() != nil {
		return -1
	}
	if err == nil {
		return 0
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode()
	}
	return -1
}

func openRootExecutable(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != 0 || stat.Nlink != 1 || stat.Mode&0o022 != 0 || stat.Mode&0o100 == 0 {
		_ = unix.Close(fd)
		return nil, errors.New("untrusted executable")
	}
	return os.NewFile(uintptr(fd), filepath.Base(path)), nil
}

func acceptCustodyConnection(ctx context.Context, listener *net.UnixListener, uid uint32) (*net.UnixConn, error) {
	deadline, ok := ctx.Deadline()
	if ok {
		_ = listener.SetDeadline(deadline)
	}
	connection, err := listener.AcceptUnix()
	if err != nil {
		return nil, err
	}
	if !peerIsOwner(connection, uid) {
		_ = connection.Close()
		return nil, errors.New("custody peer rejected")
	}
	return connection, nil
}

func (client *systemdCustodyClient) RepositoryURL() string { return "" }

func (client *systemdCustodyClient) Inventory(ctx context.Context) ([]ExpectedObject, error) {
	result := make([]ExpectedObject, 0)
	for cursor := 0; ; {
		frame, err := client.request(ctx, "inventory", struct {
			Cursor int `json:"cursor"`
		}{Cursor: cursor})
		if err != nil {
			return nil, err
		}
		var page struct {
			Objects []ExpectedObject `json:"objects"`
			Next    int              `json:"next"`
			Done    bool             `json:"done"`
		}
		if json.Unmarshal(frame.Payload, &page) != nil || page.Next < cursor || (!page.Done && page.Next <= cursor) {
			return nil, errors.New("invalid custody inventory")
		}
		result = append(result, page.Objects...)
		if int64(len(result)) > client.session.MaximumObjects {
			return nil, errors.New("custody inventory bound exceeded")
		}
		if page.Done {
			return result, nil
		}
		cursor = page.Next
	}
}

func (client *systemdCustodyClient) InventoryExpected(ctx context.Context, expected []ExpectedObject) ([]ExpectedObject, error) {
	if int64(len(expected)) > client.session.MaximumObjects {
		return nil, errors.New("custody inventory bound exceeded")
	}
	result := make([]ExpectedObject, 0, len(expected))
	var observedBytes int64
	for _, object := range expected {
		frame, err := client.request(ctx, "inventory-object", struct {
			Type string `json:"type"`
			Name string `json:"name"`
		}{Type: object.Type, Name: object.Name})
		if err != nil {
			return nil, err
		}
		var observed ExpectedObject
		if json.Unmarshal(frame.Payload, &observed) != nil || observed.Type != object.Type || observed.Name != object.Name ||
			observed.Bytes > client.session.MaximumBytes-observedBytes {
			return nil, errors.New("invalid custody inventory")
		}
		observedBytes += observed.Bytes
		result = append(result, observed)
	}
	return result, nil
}

func (client *systemdCustodyClient) Capacity(ctx context.Context) (uint64, error) {
	frame, err := client.request(ctx, "capacity", nil)
	if err != nil {
		return 0, err
	}
	var result struct {
		Free uint64 `json:"free"`
	}
	if json.Unmarshal(frame.Payload, &result) != nil {
		return 0, errors.New("invalid custody capacity")
	}
	return result.Free, nil
}

func (client *systemdCustodyClient) RunRestic(ctx context.Context, request ResticRequest, password *credentialref.Value) (ResticResult, error) {
	if password == nil || len(password.Bytes()) == 0 {
		return ResticResult{}, errors.New("restic credential unavailable")
	}
	passwordFile, err := sealedPasswordFile(password.Bytes())
	if err != nil {
		return ResticResult{}, err
	}
	defer passwordFile.Close()
	client.mu.Lock()
	defer client.mu.Unlock()
	raw, err := json.Marshal(request)
	if err != nil {
		return ResticResult{}, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = client.command.SetDeadline(deadline)
	}
	if err := writeCustodyFrame(client.command, custodyFrame{Type: "run-restic", NonceDigest: client.nonce, Payload: raw}); err != nil {
		return ResticResult{}, err
	}
	if err := sendFile(client.command, passwordFile); err != nil {
		return ResticResult{}, err
	}
	frame, err := readCustodyFrame(client.command)
	if err != nil || !frame.OK || !exactNonce(frame.NonceDigest, client.nonce) {
		return ResticResult{}, fmt.Errorf("custody restic response uncertain: %s", frame.Code)
	}
	var response resticCustodyResponse
	if json.Unmarshal(frame.Payload, &response) != nil {
		return ResticResult{}, errors.New("invalid custody restic response")
	}
	client.observation = response.Observation
	return response.Result, nil
}

func (client *systemdCustodyClient) ResticObservation() ResticObservation { return client.observation }

func (client *systemdCustodyClient) request(ctx context.Context, kind string, payload any) (custodyFrame, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	raw, _ := json.Marshal(payload)
	if deadline, ok := ctx.Deadline(); ok {
		_ = client.command.SetDeadline(deadline)
	}
	if err := writeCustodyFrame(client.command, custodyFrame{Type: kind, NonceDigest: client.nonce, Payload: raw}); err != nil {
		return custodyFrame{}, err
	}
	frame, err := readCustodyFrame(client.command)
	if err != nil || !frame.OK || !exactNonce(frame.NonceDigest, client.nonce) {
		return custodyFrame{}, fmt.Errorf("custody response uncertain: %s", frame.Code)
	}
	return frame, nil
}

func (client *systemdCustodyClient) Close(ctx context.Context) error {
	_, requestErr := client.request(ctx, "close", nil)
	_ = client.command.Close()
	_ = client.verify.Close()
	for _, path := range client.socketPaths {
		_ = os.Remove(path)
	}
	outcome := "succeeded"
	if requestErr != nil {
		outcome = "uncertain"
	}
	return errors.Join(requestErr, client.journal.FinishCustody(context.WithoutCancel(ctx), client.session, outcome))
}

func serveSystemdVerification(client *systemdCustodyClient, writer LeaseVerifier, reader ReadLeaseVerifier, retention RetentionLeaseVerifier, mutations RetainedMutationJournal) {
	serveCustodyAuthority(client.verify, client.nonce, client.session, writer, reader, retention, mutations)
}

func sendFile(socket, file *os.File) error {
	_, err := unix.SendmsgN(int(socket.Fd()), []byte{1}, unix.UnixRights(int(file.Fd())), nil, 0)
	return err
}

func receiveFile(socket *os.File) (*os.File, error) {
	data, control := make([]byte, 1), make([]byte, unix.CmsgSpace(4))
	n, controlN, _, _, err := unix.Recvmsg(int(socket.Fd()), data, control, 0)
	if err != nil || n != 1 || data[0] != 1 {
		return nil, errors.New("custody descriptor missing")
	}
	messages, err := unix.ParseSocketControlMessage(control[:controlN])
	if err != nil || len(messages) != 1 {
		return nil, errors.New("custody descriptor invalid")
	}
	fds, err := unix.ParseUnixRights(&messages[0])
	if err != nil || len(fds) != 1 {
		return nil, errors.New("custody descriptor invalid")
	}
	unix.CloseOnExec(fds[0])
	return os.NewFile(uintptr(fds[0]), "custody-restic-password"), nil
}

type noOpCustodyJournal struct{}

func (noOpCustodyJournal) BeginCustody(context.Context, CustodySession) error          { return nil }
func (noOpCustodyJournal) FinishCustody(context.Context, CustodySession, string) error { return nil }

// RunCustodySupervisor is the root-only, systemd-invoked short-lived authority.
// It owns no SQLite and accepts only the fixed policy and instance contract.
func RunCustodySupervisor(instance string) error {
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getppid() != 1 || !custodyInstancePattern.MatchString(instance) ||
		!regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(os.Getenv("INVOCATION_ID")) {
		return errors.New("custody supervisor invocation rejected")
	}
	policy, err := LoadCustodyPolicy(CustodyPolicyPath)
	if err != nil || policy.ExecutablePath == "" {
		return fmt.Errorf("custody supervisor policy rejected: %w", err)
	}
	command, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: filepath.Join(policy.RequestRoot, instance+".command.sock"), Net: "unix"})
	if err != nil {
		return err
	}
	defer command.Close()
	verify, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: filepath.Join(policy.RequestRoot, instance+".verify.sock"), Net: "unix"})
	if err != nil {
		return err
	}
	defer verify.Close()
	if !peerIsOwner(command, policy.ControllerUID) || !peerIsOwner(verify, policy.ControllerUID) {
		return errors.New("custody controller peer rejected")
	}
	commandFile, err := command.File()
	if err != nil {
		return err
	}
	defer commandFile.Close()
	verifyFile, err := verify.File()
	if err != nil {
		return err
	}
	defer verifyFile.Close()
	var launch custodyLaunch
	launchFrame, err := readCustodyFrame(commandFile)
	if err != nil || launchFrame.Type != "launch" || strictUnmarshal(launchFrame.Payload, &launch) != nil || !exactNonce(launchFrame.NonceDigest, launch.Session.NonceDigest) {
		return errors.New("custody launch invalid")
	}
	nonce, err := hex.DecodeString(launch.Nonce)
	if err != nil || !exactNonce(custodyNonceDigest(nonce), launch.Session.NonceDigest) || !launch.Session.valid(time.Now(), policy.MaximumLifetime) {
		return errors.New("custody session authentication failed")
	}
	if err := VerifyCustodyPaths(policy, launch.Session.Role); err != nil {
		return fmt.Errorf("custody supervisor paths rejected: %w", err)
	}
	remote := &remoteLeaseVerifier{file: verifyFile, nonce: launch.Session.NonceDigest}
	innerLauncher := CustodyLauncher{PolicyPath: CustodyPolicyPath, Writer: remote, Reader: remote, Retention: remote, Mutations: remote, Journal: noOpCustodyJournal{}}
	inner, err := innerLauncher.startDirect(context.Background(), launch.Session)
	if err != nil {
		return fmt.Errorf("custody inner launch rejected: %w", err)
	}
	defer inner.Close(context.Background())
	return serveCustodySupervisor(commandFile, launch, policy, inner)
}

func serveCustodySupervisor(command *os.File, launch custodyLaunch, policy CustodyPolicy, inner CustodyClient) error {
	runner := NewResticRunner().(*resticRunner)
	leaseContext, cancel := context.WithDeadline(context.Background(), launch.Session.MaximumExpiresAt)
	defer cancel()
	for {
		frame, err := readCustodyFrame(command)
		if err != nil {
			return err
		}
		if !exactNonce(frame.NonceDigest, launch.Session.NonceDigest) {
			return errors.New("custody command authentication failed")
		}
		response := custodyFrame{Type: frame.Type + "-result", NonceDigest: launch.Session.NonceDigest, OK: true}
		switch frame.Type {
		case "ready":
		case "inventory":
			var request struct {
				Cursor int `json:"cursor"`
			}
			if strictUnmarshal(frame.Payload, &request) != nil {
				response.OK, response.Code = false, "inventory-invalid"
				break
			}
			objects, callErr := inner.Inventory(leaseContext)
			if callErr != nil || request.Cursor < 0 || request.Cursor > len(objects) {
				response.OK, response.Code = false, "inventory-invalid"
				break
			}
			end := request.Cursor + 64
			if end > len(objects) {
				end = len(objects)
			}
			response.Payload, _ = json.Marshal(struct {
				Objects []ExpectedObject `json:"objects"`
				Next    int              `json:"next"`
				Done    bool             `json:"done"`
			}{objects[request.Cursor:end], end, end == len(objects)})
		case "inventory-object":
			var request struct {
				Type string `json:"type"`
				Name string `json:"name"`
			}
			if strictUnmarshal(frame.Payload, &request) != nil {
				response.OK, response.Code = false, "inventory-invalid"
				break
			}
			objects, callErr := inner.InventoryExpected(leaseContext, []ExpectedObject{{Type: request.Type, Name: request.Name}})
			if callErr != nil || len(objects) != 1 {
				response.OK, response.Code = false, "inventory-invalid"
			} else {
				response.Payload, _ = json.Marshal(objects[0])
			}
		case "capacity":
			free, callErr := inner.Capacity(leaseContext)
			if callErr != nil {
				response.OK, response.Code = false, "capacity-unavailable"
			} else {
				response.Payload, _ = json.Marshal(struct {
					Free uint64 `json:"free"`
				}{free})
			}
		case "run-restic":
			passwordFile, descriptorErr := receiveFile(command)
			if descriptorErr != nil {
				return descriptorErr
			}
			var result ResticResult
			var request ResticRequest
			decodeErr := strictUnmarshal(frame.Payload, &request)
			if decodeErr == nil {
				result, decodeErr = runBrokeredRestic(policy, launch.Session, inner.RepositoryURL(), &request, func() (ResticResult, error) {
					return runner.runSealed(leaseContext, request, passwordFile)
				})
			}
			_ = passwordFile.Close()
			if decodeErr != nil {
				response.OK, response.Code = false, "restic-"+request.Mode+"-failed"
			} else {
				response.Payload, _ = json.Marshal(resticCustodyResponse{Result: result, Observation: runner.Observation()})
			}
		case "close":
			closeErr := inner.Close(context.Background())
			if closeErr != nil {
				response.OK, response.Code = false, "close-uncertain"
			}
			_ = writeCustodyFrame(command, response)
			return closeErr
		default:
			response.OK, response.Code = false, "command-invalid"
		}
		if err := writeCustodyFrame(command, response); err != nil {
			return err
		}
	}
}

type exchangeTransfer struct {
	directory *os.File
	snapshot  *os.File
	uid       uint32
	gid       uint32
}

func (transfer *exchangeTransfer) Close() error {
	if transfer == nil {
		return nil
	}
	var errs []error
	if transfer.snapshot != nil {
		errs = append(errs, transfer.snapshot.Close())
		transfer.snapshot = nil
	}
	if transfer.directory != nil {
		errs = append(errs, transfer.directory.Close())
		transfer.directory = nil
	}
	return errors.Join(errs...)
}

func (transfer *exchangeTransfer) ReturnOwnership() error {
	if transfer == nil || transfer.directory == nil {
		return nil
	}
	if transfer.snapshot != nil {
		return errors.Join(
			unix.Fchown(int(transfer.snapshot.Fd()), int(transfer.uid), int(transfer.gid)),
			unix.Fchown(int(transfer.directory.Fd()), int(transfer.uid), int(transfer.gid)),
		)
	}
	return chownDescriptorTree(int(transfer.directory.Fd()), transfer.uid, transfer.gid)
}

func runBrokeredRestic(policy CustodyPolicy, session CustodySession, repositoryURL string, request *ResticRequest, run func() (ResticResult, error)) (ResticResult, error) {
	if run == nil {
		return ResticResult{}, errors.New("restic runner unavailable")
	}
	transfer, err := prepareBrokeredRestic(policy, session, repositoryURL, request)
	if err != nil {
		return ResticResult{}, err
	}
	if transfer != nil {
		defer transfer.Close()
	}
	result, runErr := run()
	return result, errors.Join(runErr, transfer.ReturnOwnership())
}

func prepareBrokeredRestic(policy CustodyPolicy, session CustodySession, repositoryURL string, request *ResticRequest) (*exchangeTransfer, error) {
	root := policy.StandardRoot
	if session.RepositoryClass == "critical" {
		root = policy.CriticalRoot
	}
	if request == nil || request.BinaryPath != policy.ResticBinaryPath || request.RepositoryURL != "" || request.RepositoryID != session.RepositoryID ||
		request.RepositoryClass != session.RepositoryClass || request.RepositoryRoot != root || request.ExchangeRoot != policy.ExchangeRoot ||
		request.ExecutionUID != policy.ResticUID || request.ExecutionGID != policy.ResticUID || request.ControllerUID != policy.ControllerUID {
		return nil, errors.New("restic request outside custody policy")
	}
	switch request.Mode {
	case "backup":
		transfer, err := prepareBackupExchange(policy, request.SnapshotPath)
		if err != nil {
			return nil, err
		}
		request.RepositoryURL = repositoryURL
		return transfer, nil
	case "restore":
		transfer, err := prepareRestoreExchange(policy, request.RestoreTarget)
		if err != nil {
			return nil, err
		}
		request.RepositoryURL = repositoryURL
		return transfer, nil
	case "init", "config", "snapshots", "check-full":
		if request.SnapshotPath != "" || request.RestoreTarget != "" {
			return nil, errors.New("unexpected exchange path")
		}
		request.RepositoryURL = repositoryURL
		return nil, nil
	case "forget-dry-run", "forget", "prune":
		if session.Role != "retention" || request.SnapshotPath != "" || request.RestoreTarget != "" {
			return nil, errors.New("retention restic outside custody policy")
		}
		request.RepositoryURL = repositoryURL
		return nil, nil
	default:
		return nil, errors.New("restic mode outside custody policy")
	}
}

func prepareBackupExchange(policy CustodyPolicy, snapshotPath string) (*exchangeTransfer, error) {
	return prepareBackupExchangeWithHook(policy, snapshotPath, nil)
}

func prepareBackupExchangeWithHook(policy CustodyPolicy, snapshotPath string, afterValidation func() error) (*exchangeTransfer, error) {
	parent := filepath.Dir(snapshotPath)
	if !exactExchangeChild(policy.ExchangeRoot, parent, ".vsk-backup-staging-") || snapshotPath != filepath.Join(parent, "database.sqlite") {
		return nil, errors.New("backup exchange outside custody policy")
	}
	parentFile, err := openExchangeChild(policy, filepath.Base(parent), true)
	if err != nil {
		return nil, errors.New("backup exchange rejected")
	}
	transfer := &exchangeTransfer{directory: parentFile, uid: policy.ControllerUID, gid: policy.ControllerUID}
	fail := func(err error) (*exchangeTransfer, error) {
		_ = transfer.Close()
		return nil, err
	}
	if err := validateExchangeDescriptor(int(parentFile.Fd()), true, policy.ControllerUID, 0o700); err != nil {
		return fail(errors.New("backup exchange rejected"))
	}
	names, err := descriptorNames(int(parentFile.Fd()))
	if err != nil || len(names) != 1 || names[0] != "database.sqlite" {
		return fail(errors.New("backup exchange contents rejected"))
	}
	snapshotFile, err := openBeneath(int(parentFile.Fd()), "database.sqlite", false)
	if err != nil {
		return fail(errors.New("backup snapshot rejected"))
	}
	transfer.snapshot = snapshotFile
	if err := validateExchangeDescriptor(int(snapshotFile.Fd()), false, policy.ControllerUID, 0o600); err != nil {
		return fail(errors.New("backup snapshot rejected"))
	}
	if afterValidation != nil {
		if err := afterValidation(); err != nil {
			return fail(err)
		}
	}
	if err := unix.Fchown(int(snapshotFile.Fd()), int(policy.ResticUID), int(policy.ResticUID)); err != nil {
		return fail(err)
	}
	if err := unix.Fchown(int(parentFile.Fd()), int(policy.ResticUID), int(policy.ResticUID)); err != nil {
		_ = unix.Fchown(int(snapshotFile.Fd()), int(policy.ControllerUID), int(policy.ControllerUID))
		return fail(err)
	}
	return transfer, nil
}

func prepareRestoreExchange(policy CustodyPolicy, target string) (*exchangeTransfer, error) {
	return prepareRestoreExchangeWithHook(policy, target, nil)
}

func prepareRestoreExchangeWithHook(policy CustodyPolicy, target string, afterValidation func() error) (*exchangeTransfer, error) {
	if !exactExchangeChild(policy.ExchangeRoot, target, ".vsk-backup-verify-") {
		return nil, errors.New("restore exchange outside custody policy")
	}
	targetFile, err := openExchangeChild(policy, filepath.Base(target), true)
	if err != nil {
		return nil, errors.New("restore exchange rejected")
	}
	transfer := &exchangeTransfer{directory: targetFile, uid: policy.ControllerUID, gid: policy.ControllerUID}
	if err := validateExchangeDescriptor(int(targetFile.Fd()), true, policy.ControllerUID, 0o700); err != nil {
		_ = transfer.Close()
		return nil, errors.New("restore exchange rejected")
	}
	names, err := descriptorNames(int(targetFile.Fd()))
	if err != nil || len(names) != 0 {
		_ = transfer.Close()
		return nil, errors.New("restore exchange is not empty")
	}
	if afterValidation != nil {
		if err := afterValidation(); err != nil {
			_ = transfer.Close()
			return nil, err
		}
	}
	if err := unix.Fchown(int(targetFile.Fd()), int(policy.ResticUID), int(policy.ResticUID)); err != nil {
		_ = transfer.Close()
		return nil, err
	}
	return transfer, nil
}

func exactExchangeChild(root, path, prefix string) bool {
	return filepath.IsAbs(root) && filepath.IsAbs(path) && filepath.Clean(root) == root && filepath.Clean(path) == path &&
		filepath.Dir(path) == root && strings.HasPrefix(filepath.Base(path), prefix) && filepath.Base(path) != prefix
}

func openExchangeChild(policy CustodyPolicy, name string, directory bool) (*os.File, error) {
	rootFD, err := openCustodyPath(policy.ExchangeRoot, true, policy.ControllerUID)
	if err != nil {
		return nil, err
	}
	defer unix.Close(rootFD)
	return openBeneath(rootFD, name, directory)
}

func openBeneath(rootFD int, name string, directory bool) (*os.File, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsRune(name, '/') || strings.ContainsRune(name, 0) {
		return nil, unix.EINVAL
	}
	flags := uint64(unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK)
	if directory {
		flags |= unix.O_DIRECTORY
	}
	fd, err := unix.Openat2(rootFD, name, &unix.OpenHow{Flags: flags,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "custody-exchange")
	if file == nil {
		_ = unix.Close(fd)
		return nil, unix.EBADF
	}
	return file, nil
}

func validateExchangeDescriptor(fd int, directory bool, uid uint32, mode uint32) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Uid != uid || stat.Mode&0o7777 != mode {
		return unix.EPERM
	}
	want := uint32(unix.S_IFREG)
	if directory {
		want = unix.S_IFDIR
	}
	if stat.Mode&unix.S_IFMT != want || (!directory && stat.Nlink != 1) {
		return unix.EPERM
	}
	return nil
}

func descriptorNames(fd int) ([]string, error) {
	if _, err := unix.Seek(fd, 0, 0); err != nil {
		return nil, err
	}
	duplicate, err := unix.Dup(fd)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(duplicate), "custody-exchange-list")
	if file == nil {
		_ = unix.Close(duplicate)
		return nil, unix.EBADF
	}
	defer file.Close()
	names, err := file.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	return names, nil
}

func chownDescriptorTree(fd int, uid, gid uint32) error {
	names, err := descriptorNames(fd)
	if err != nil {
		return err
	}
	for _, name := range names {
		child, err := openBeneath(fd, name, false)
		if err != nil {
			return err
		}
		var stat unix.Stat_t
		statErr := unix.Fstat(int(child.Fd()), &stat)
		if statErr == nil {
			switch stat.Mode & unix.S_IFMT {
			case unix.S_IFDIR:
				statErr = chownDescriptorTree(int(child.Fd()), uid, gid)
			case unix.S_IFREG:
				if stat.Nlink != 1 {
					statErr = unix.EPERM
				}
			default:
				statErr = unix.EPERM
			}
		}
		if statErr == nil {
			statErr = unix.Fchown(int(child.Fd()), int(uid), int(gid))
		}
		closeErr := child.Close()
		if err := errors.Join(statErr, closeErr); err != nil {
			return err
		}
	}
	return unix.Fchown(fd, int(uid), int(gid))
}

func ownerUID(info os.FileInfo) uint32 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return stat.Uid
	}
	return ^uint32(0)
}

func ownerUIDOrInvalid(info os.FileInfo) uint32 {
	if info == nil {
		return ^uint32(0)
	}
	return ownerUID(info)
}

func modeOf(info os.FileInfo) os.FileMode {
	if info == nil {
		return 0
	}
	return info.Mode()
}

func strictUnmarshal(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("trailing custody data")
	}
	return nil
}

//go:build linux

package backup

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"golang.org/x/sys/unix"
)

const (
	custodySessionFD = 3
	custodyRESTFD    = 4
	custodyVerifyFD  = 5
	custodyCommandFD = 6
)

type CustodyJournal interface {
	BeginCustody(context.Context, CustodySession) error
	FinishCustody(context.Context, CustodySession, string) error
}

type CustodyLauncher struct {
	PolicyPath string
	Writer     LeaseVerifier
	Reader     ReadLeaseVerifier
	Retention  RetentionLeaseVerifier
	Mutations  RetainedMutationJournal
	Journal    CustodyJournal
	Clock      func() time.Time
	// command is test-only; production always executes this same vsk-labs
	// binary in its hidden, operation-bounded custody mode.
	command []string
}

type CustodyClient interface {
	RepositoryURL() string
	Inventory(context.Context) ([]ExpectedObject, error)
	InventoryExpected(context.Context, []ExpectedObject) ([]ExpectedObject, error)
	Capacity(context.Context) (uint64, error)
	CapacitySnapshot(context.Context) (RepositoryCapacity, error)
	RunRestic(context.Context, ResticRequest, *credentialref.Value) (ResticResult, error)
	RunOffsiteRestic(context.Context, OffsiteResticRequest, *credentialref.Value, []byte) (OffsiteResticResult, error)
	ResticObservation() ResticObservation
	Close(context.Context) error
}

type RepositoryCapacity struct {
	TotalBytes       uint64 `json:"totalBytes"`
	AvailableBytes   uint64 `json:"availableBytes"`
	QuarantinedBytes uint64 `json:"quarantinedBytes"`
}

type processCustodyClient struct {
	session  CustodySession
	nonce    string
	socket   string
	command  *os.File
	verify   *os.File
	cmd      *exec.Cmd
	journal  CustodyJournal
	mu       sync.Mutex
	done     chan error
	poisoned atomic.Bool
}

type custodyLaunch struct {
	Session CustodySession `json:"session"`
	Nonce   string         `json:"nonce"`
}

func (launcher CustodyLauncher) Start(ctx context.Context, session CustodySession) (CustodyClient, error) {
	policy, err := LoadCustodyPolicy(launcher.PolicyPath)
	if err != nil {
		return nil, errors.New("custody launch rejected")
	}
	if uint32(os.Geteuid()) == policy.ControllerUID {
		return launcher.startSystemd(ctx, policy, session)
	}
	if os.Geteuid() == 0 && len(launcher.command) > 0 {
		return launcher.startDirect(ctx, session)
	}
	return nil, errors.New("custody controller identity rejected")
}

func (launcher CustodyLauncher) startDirect(ctx context.Context, session CustodySession) (CustodyClient, error) {
	if session.Role == "offsite-writer" {
		return nil, errors.New("offsite custody requires systemd broker")
	}
	policy, err := LoadCustodyPolicy(launcher.PolicyPath)
	if err != nil ||
		(session.Role == "writer" && launcher.Writer == nil) || (session.Role == "verifier" && launcher.Reader == nil) || (session.Role == "retention" && (launcher.Retention == nil || launcher.Mutations == nil)) || launcher.Journal == nil {
		return nil, errors.New("custody launch rejected")
	}
	if err := VerifyCustodyPaths(policy, session.Role); err != nil {
		return nil, err
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
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

	sessionRead, sessionWrite, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer sessionWrite.Close()
	verifyParent, verifyChild, err := socketPair("custody-verify")
	if err != nil {
		_ = sessionRead.Close()
		return nil, err
	}
	commandParent, commandChild, err := socketPair("custody-command")
	if err != nil {
		_ = sessionRead.Close()
		_ = verifyParent.Close()
		_ = verifyChild.Close()
		return nil, err
	}
	runtimeDir, err := os.MkdirTemp("/run", "vsk-custody-")
	if err != nil {
		_ = sessionRead.Close()
		_ = verifyParent.Close()
		_ = verifyChild.Close()
		_ = commandParent.Close()
		_ = commandChild.Close()
		return nil, err
	}
	if err := os.Chmod(runtimeDir, 0o711); err != nil {
		_ = os.RemoveAll(runtimeDir)
		return nil, err
	}
	socketPath := filepath.Join(runtimeDir, "rest.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		_ = os.RemoveAll(runtimeDir)
		return nil, err
	}
	unixListener := listener.(*net.UnixListener)
	unixListener.SetUnlinkOnClose(false)
	restFile, err := unixListener.File()
	_ = listener.Close()
	if err != nil {
		_ = os.RemoveAll(runtimeDir)
		return nil, err
	}
	if err := os.Chown(socketPath, int(policy.ResticUID), int(policy.ResticUID)); err != nil {
		_ = restFile.Close()
		_ = os.RemoveAll(runtimeDir)
		return nil, fmt.Errorf("custody socket ownership failed: %w", err)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = restFile.Close()
		_ = os.RemoveAll(runtimeDir)
		return nil, fmt.Errorf("custody socket mode failed: %w", err)
	}

	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	argv := []string{"backup-custody", "--policy", launcher.PolicyPath}
	if len(launcher.command) > 0 {
		executable, argv = launcher.command[0], launcher.command[1:]
	}
	cmd := exec.CommandContext(ctx, executable, argv...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "VSK_BACKUP_CUSTODY=1", "VSK_BACKUP_CUSTODY_POLICY=" + launcher.PolicyPath}
	cmd.ExtraFiles = []*os.File{sessionRead, restFile, verifyChild, commandChild}
	cmd.Stdout = io.Discard
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: policy.OwnerUID, Gid: policy.OwnerGID}, Setsid: true}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	_ = sessionRead.Close()
	_ = restFile.Close()
	_ = verifyChild.Close()
	_ = commandChild.Close()
	launch := custodyLaunch{Session: session, Nonce: hex.EncodeToString(nonce)}
	if err := json.NewEncoder(sessionWrite).Encode(launch); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, err
	}
	_ = sessionWrite.Close()
	client := &processCustodyClient{session: session, nonce: session.NonceDigest, socket: socketPath,
		command: commandParent, verify: verifyParent, cmd: cmd, journal: launcher.Journal, done: make(chan error, 1)}
	go client.serveVerification(launcher.Writer, launcher.Reader, launcher.Retention, launcher.Mutations)
	go func() { client.done <- cmd.Wait(); close(client.done) }()
	readyCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := client.request(readyCtx, "ready", nil); err != nil {
		_ = cmd.Process.Kill()
		return nil, err
	}
	failed = false
	return client, nil
}

func (client *processCustodyClient) RepositoryURL() string {
	return "http+unix://" + client.socket + ":/" + client.session.RepositoryID + "/"
}

func (client *processCustodyClient) Inventory(ctx context.Context) ([]ExpectedObject, error) {
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

func (client *processCustodyClient) InventoryExpected(ctx context.Context, expected []ExpectedObject) ([]ExpectedObject, error) {
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

func (client *processCustodyClient) Capacity(ctx context.Context) (uint64, error) {
	snapshot, err := client.CapacitySnapshot(ctx)
	return snapshot.AvailableBytes, err
}

func (client *processCustodyClient) CapacitySnapshot(ctx context.Context) (RepositoryCapacity, error) {
	frame, err := client.request(ctx, "capacity", nil)
	if err != nil {
		return RepositoryCapacity{}, err
	}
	var result RepositoryCapacity
	if json.Unmarshal(frame.Payload, &result) != nil {
		return RepositoryCapacity{}, errors.New("invalid custody capacity")
	}
	if result.TotalBytes == 0 || result.AvailableBytes > result.TotalBytes || result.QuarantinedBytes > result.TotalBytes-result.AvailableBytes {
		return RepositoryCapacity{}, errors.New("invalid custody capacity")
	}
	return result, nil
}

func (*processCustodyClient) RunRestic(context.Context, ResticRequest, *credentialref.Value) (ResticResult, error) {
	return ResticResult{}, errors.New("direct custody client cannot broker restic")
}
func (*processCustodyClient) RunOffsiteRestic(context.Context, OffsiteResticRequest, *credentialref.Value, []byte) (OffsiteResticResult, error) {
	return OffsiteResticResult{}, errors.New("direct custody client cannot broker offsite restic")
}
func (*processCustodyClient) ResticObservation() ResticObservation { return ResticObservation{} }

func (client *processCustodyClient) Close(ctx context.Context) error {
	_, requestErr := client.request(ctx, "close", nil)
	var poisonErr error
	if client.poisoned.Load() {
		poisonErr = errors.New("retention journal uncertain")
	}
	_ = client.command.Close()
	_ = client.verify.Close()
	var waitErr error
	select {
	case waitErr = <-client.done:
	case <-ctx.Done():
		waitErr = ctx.Err()
		_ = client.cmd.Process.Kill()
	}
	outcome := "succeeded"
	if requestErr != nil || waitErr != nil || poisonErr != nil {
		outcome = "uncertain"
	}
	journalErr := client.journal.FinishCustody(context.WithoutCancel(ctx), client.session, outcome)
	_ = os.RemoveAll(filepath.Dir(client.socket))
	return errors.Join(requestErr, waitErr, poisonErr, journalErr)
}

func (client *processCustodyClient) request(ctx context.Context, kind string, payload any) (custodyFrame, error) {
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
	if err != nil || !exactNonce(frame.NonceDigest, client.nonce) || !frame.OK {
		return custodyFrame{}, fmt.Errorf("custody response uncertain: %s", frame.Code)
	}
	return frame, nil
}

func (client *processCustodyClient) serveVerification(writer LeaseVerifier, reader ReadLeaseVerifier, retention RetentionLeaseVerifier, mutations RetainedMutationJournal) {
	serveCustodyAuthority(client.verify, client.nonce, client.session, writer, reader, retention, mutations, func() { client.poisoned.Store(true) })
}

func serveCustodyAuthority(file *os.File, nonce string, session CustodySession, writer LeaseVerifier, reader ReadLeaseVerifier, retention RetentionLeaseVerifier, mutations RetainedMutationJournal, poison func()) {
	for {
		frame, err := readCustodyFrame(file)
		if err != nil {
			return
		}
		response := custodyFrame{Type: frame.Type + "-result", NonceDigest: nonce}
		if !exactNonce(frame.NonceDigest, nonce) {
			_ = writeCustodyFrame(file, response)
			continue
		}
		switch frame.Type {
		case "verify":
			if (session.Role == "writer" || session.Role == "offsite-writer") && writer != nil {
				response.OK = writer.VerifyWriterLease(*session.WriterLease, time.Now()) == nil
			}
			if session.Role == "verifier" && reader != nil {
				response.OK = reader.VerifyReadLease(*session.ReadLease, time.Now()) == nil
			}
			if session.Role == "retention" && retention != nil {
				response.OK = retention.VerifyRetentionLease(*session.RetentionLease, time.Now()) == nil
			}
		case "mutation-begin":
			var request RetainedMutationAttempt
			response.OK = session.Role == "retention" && mutations != nil && strictUnmarshal(frame.Payload, &request) == nil && mutations.BeginRetainedMutation(context.Background(), request) == nil
			if !response.OK && poison != nil {
				poison()
			}
		case "mutation-finish":
			var request RetainedMutationOutcome
			response.OK = session.Role == "retention" && mutations != nil && strictUnmarshal(frame.Payload, &request) == nil && mutations.FinishRetainedMutation(context.Background(), request) == nil
			if !response.OK && poison != nil {
				poison()
			}
		}
		_ = writeCustodyFrame(file, response)
	}
}

type remoteLeaseVerifier struct {
	file  *os.File
	nonce string
	mu    sync.Mutex
}

func (v *remoteLeaseVerifier) request(kind string, payload any) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if err := writeCustodyFrame(v.file, custodyFrame{Type: kind, NonceDigest: v.nonce, Payload: raw}); err != nil {
		return err
	}
	frame, err := readCustodyFrame(v.file)
	if err != nil || frame.Type != kind+"-result" || !frame.OK || !exactNonce(frame.NonceDigest, v.nonce) {
		return errors.New("custody authority rejected")
	}
	return nil
}
func (v *remoteLeaseVerifier) verify() error                                  { return v.request("verify", nil) }
func (v *remoteLeaseVerifier) VerifyWriterLease(WriterLease, time.Time) error { return v.verify() }
func (v *remoteLeaseVerifier) VerifyReadLease(ReadLease, time.Time) error     { return v.verify() }
func (v *remoteLeaseVerifier) VerifyRetentionLease(RetentionLease, time.Time) error {
	return v.verify()
}
func (v *remoteLeaseVerifier) BeginRetainedMutation(_ context.Context, request RetainedMutationAttempt) error {
	return v.request("mutation-begin", request)
}
func (v *remoteLeaseVerifier) FinishRetainedMutation(_ context.Context, request RetainedMutationOutcome) error {
	return v.request("mutation-finish", request)
}

// RunCustodyChild is called only by the hidden same-binary mode before normal
// CLI construction. Its inherited descriptors are the complete authority.
func RunCustodyChild(policyPath string) error {
	if os.Getenv("VSK_BACKUP_CUSTODY") != "1" || os.Geteuid() == 0 {
		return errors.New("custody child identity rejected")
	}
	policy, err := LoadCustodyPolicy(policyPath)
	if err != nil || uint32(os.Geteuid()) != policy.OwnerUID || uint32(os.Getegid()) != policy.OwnerGID {
		return errors.New("custody child policy rejected")
	}
	var launch custodyLaunch
	if err := json.NewDecoder(os.NewFile(custodySessionFD, "custody-session")).Decode(&launch); err != nil {
		return err
	}
	nonce, err := hex.DecodeString(launch.Nonce)
	if err != nil || !exactNonce(custodyNonceDigest(nonce), launch.Session.NonceDigest) || !launch.Session.valid(time.Now(), policy.MaximumLifetime) {
		return errors.New("custody session authentication failed")
	}
	if err := verifyRepositoryCustodyPaths(policy, launch.Session.Role); err != nil {
		return err
	}
	root := policy.StandardRoot
	quarantine := policy.StandardQuarantine
	if launch.Session.RepositoryClass == "critical" {
		root = policy.CriticalRoot
		quarantine = policy.CriticalQuarantine
	} else if launch.Session.RepositoryClass != "standard" {
		return errors.New("custody class rejected")
	}
	lockFD, err := unix.Open(filepath.Join(root, ".vsk-custody.lock"), unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer unix.Close(lockFD)
	if err := unix.Flock(lockFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return errors.New("second custodian rejected")
	}
	verify := os.NewFile(custodyVerifyFD, "custody-verify")
	command := os.NewFile(custodyCommandFD, "custody-command")
	if !filePeerHasUID(verify, 0) || !filePeerHasUID(command, 0) {
		return errors.New("custody launcher peer rejected")
	}
	listenerFile := os.NewFile(custodyRESTFD, "custody-rest")
	listener, err := net.FileListener(listenerFile)
	if err != nil {
		return err
	}
	remote := &remoteLeaseVerifier{file: verify, nonce: launch.Session.NonceDigest}
	rest, err := newCustodyRESTServer(root, quarantine, policy.OwnerUID, policy.ResticUID, launch.Session, remote, remote, remote, remote, time.Now)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithDeadline(context.Background(), launch.Session.MaximumExpiresAt)
	defer cancel()
	serveDone := make(chan error, 1)
	go func() { serveDone <- rest.Serve(ctx, listener) }()
	var inventoriedObjects, inventoriedBytes int64
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
			decoder := json.NewDecoder(bytes.NewReader(frame.Payload))
			decoder.DisallowUnknownFields()
			objects, inventoryErr := custodyInventory(root, policy.OwnerUID, launch.Session.MaximumObjects, launch.Session.MaximumBytes)
			if decoder.Decode(&request) != nil || request.Cursor < 0 || request.Cursor > len(objects) || inventoryErr != nil {
				response.OK = false
				response.Code = "inventory-invalid"
			} else {
				end := request.Cursor + 64
				if end > len(objects) {
					end = len(objects)
				}
				response.Payload, _ = json.Marshal(struct {
					Objects []ExpectedObject `json:"objects"`
					Next    int              `json:"next"`
					Done    bool             `json:"done"`
				}{Objects: objects[request.Cursor:end], Next: end, Done: end == len(objects)})
			}
		case "inventory-object":
			var request struct {
				Type string `json:"type"`
				Name string `json:"name"`
			}
			decoder := json.NewDecoder(bytes.NewReader(frame.Payload))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&request) != nil {
				response.OK = false
				response.Code = "inventory-invalid"
				break
			}
			object, inventoryErr := custodyExpectedObject(root, policy.OwnerUID, request.Type, request.Name)
			if inventoryErr != nil || inventoriedObjects >= launch.Session.MaximumObjects || object.Bytes > launch.Session.MaximumBytes-inventoriedBytes {
				response.OK = false
				response.Code = "inventory-invalid"
			} else {
				inventoriedObjects++
				inventoriedBytes += object.Bytes
				response.Payload, _ = json.Marshal(object)
			}
		case "capacity":
			capacity, capacityErr := custodyFilesystemCapacity(root, quarantine)
			if capacityErr != nil {
				response.OK = false
				response.Code = "capacity-unavailable"
			} else {
				response.Payload, _ = json.Marshal(capacity)
			}
		case "close":
			poisoned := rest.retentionSessionPoisoned()
			cancel()
			_ = writeCustodyFrame(command, response)
			serveErr := <-serveDone
			if poisoned {
				return errors.Join(errors.New("retention journal uncertain"), serveErr)
			}
			return serveErr
		default:
			response.OK = false
		}
		if err := writeCustodyFrame(command, response); err != nil {
			return err
		}
	}
}

func socketPair(name string) (*os.File, *os.File, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	return os.NewFile(uintptr(fds[0]), name+"-parent"), os.NewFile(uintptr(fds[1]), name+"-child"), nil
}

func filePeerHasUID(file *os.File, uid uint32) bool {
	credentials, err := unix.GetsockoptUcred(int(file.Fd()), unix.SOL_SOCKET, unix.SO_PEERCRED)
	return err == nil && credentials != nil && credentials.Uid == uid
}
func nowOr(clock func() time.Time) time.Time {
	if clock != nil {
		return clock()
	}
	return time.Now()
}

func custodyFilesystemCapacity(root, quarantine string) (RepositoryCapacity, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(root, &stat); err != nil {
		return RepositoryCapacity{}, err
	}
	var quarantined uint64
	err := filepath.WalkDir(quarantine, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("quarantine symlink rejected")
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() < 0 {
			return errors.New("invalid quarantine object")
		}
		if uint64(info.Size()) > ^uint64(0)-quarantined {
			return errors.New("quarantine capacity overflow")
		}
		quarantined += uint64(info.Size())
		return nil
	})
	if err != nil {
		return RepositoryCapacity{}, err
	}
	return RepositoryCapacity{TotalBytes: stat.Blocks * uint64(stat.Bsize), AvailableBytes: stat.Bavail * uint64(stat.Bsize), QuarantinedBytes: quarantined}, nil
}

func custodyInventory(root string, owner uint32, maxObjects, maxBytes int64) ([]ExpectedObject, error) {
	objects, err := inventoryRepository(root, owner)
	if err != nil || int64(len(objects)) > maxObjects {
		return nil, errors.New("custody inventory bound exceeded")
	}
	var bytes int64
	for _, object := range objects {
		if object.Bytes > maxBytes-bytes {
			return nil, errors.New("custody byte bound exceeded")
		}
		bytes += object.Bytes
	}
	return objects, nil
}

func inventoryRepository(root string, owner uint32) ([]ExpectedObject, error) {
	rootFD, err := unix.Openat2(unix.AT_FDCWD, root, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, err
	}
	defer unix.Close(rootFD)
	var result []ExpectedObject
	if object, err := custodyHashObject(rootFD, "config", "config", owner); err == nil {
		result = append(result, object)
	} else if !errors.Is(err, unix.ENOENT) {
		return nil, err
	}
	for _, kind := range []string{"keys", "data", "index", "snapshots"} {
		fd, err := unix.Openat(rootFD, kind, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return nil, err
		}
		dir := os.NewFile(uintptr(fd), kind)
		if dir == nil {
			_ = unix.Close(fd)
			return nil, errors.New("unsafe custody directory")
		}
		names, err := dir.Readdirnames(-1)
		if err != nil {
			_ = dir.Close()
			return nil, err
		}
		sort.Strings(names)
		for _, name := range names {
			object, err := custodyHashObject(fd, kind, name, owner)
			if err != nil {
				_ = dir.Close()
				return nil, err
			}
			result = append(result, object)
		}
		if err := dir.Close(); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func custodyExpectedObject(root string, owner uint32, kind, name string) (ExpectedObject, error) {
	rootFD, err := unix.Openat2(unix.AT_FDCWD, root, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return ExpectedObject{}, err
	}
	defer unix.Close(rootFD)
	if kind == "config" && name == "config" {
		return custodyHashObject(rootFD, kind, name, owner)
	}
	if _, allowed := retainedObjectTypes[kind]; !allowed || !validObjectName(name) {
		return ExpectedObject{}, errors.New("unsafe custody object reference")
	}
	directoryFD, err := unix.Openat(rootFD, kind, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return ExpectedObject{}, err
	}
	defer unix.Close(directoryFD)
	return custodyHashObject(directoryFD, kind, name, owner)
}

func custodyHashObject(directory int, kind, name string, owner uint32) (ExpectedObject, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") {
		return ExpectedObject{}, errors.New("unsafe custody object")
	}
	fd, err := unix.Openat(directory, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return ExpectedObject{}, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return ExpectedObject{}, errors.New("unsafe custody object")
	}
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != owner || !isLocalDescriptor(fd) {
		return ExpectedObject{}, errors.New("unsafe custody object")
	}
	hash := sha256.New()
	bytes, err := io.Copy(hash, file)
	if err != nil {
		return ExpectedObject{}, err
	}
	return ExpectedObject{Type: kind, Name: name, Bytes: bytes, Digest: "sha256:" + hex.EncodeToString(hash.Sum(nil))}, nil
}

//go:build linux

package qualification

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/linuxrole"
	"golang.org/x/sys/unix"
)

const fixtureControlDatabase = "/var/lib/vsk-labs/control/control.db"
const fixtureControlProfile = "/etc/vsk-labs/control/server.json"
const fixtureControlCredentials = "/run/vsk-labs-control-credentials"
const fixtureSetupWitnessPath = slackFixtureDirectory + "/control-setup-observation.json"

// The peer owns only these subprocess handles. The foreground child is the
// ordinary database owner; neither this supervisor nor its witness opens SQLite.
type fixtureControlChild struct {
	cmd    *exec.Cmd
	done   chan struct{}
	err    error
	start  string
	output fixturePrivateOutput
}
type fixturePrivateOutput struct {
	mu   sync.Mutex
	data []byte
}

func (o *fixturePrivateOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.data)+len(p) > 65536 {
		return 0, ErrUnavailable
	}
	o.data = append(o.data, p...)
	return len(p), nil
}
func (o *fixturePrivateOutput) bytes() []byte {
	o.mu.Lock()
	defer o.mu.Unlock()
	return bytes.Clone(o.data)
}
func fixtureStartIdentity(pid int) (string, error) {
	ticks, e := processStart(pid)
	if e != nil {
		return "", e
	}
	boot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil {
		return "", e
	}
	return hostaction.Digest(map[string]string{"boot": strings.TrimSpace(string(boot)), "start": strconv.FormatUint(ticks, 10)}), nil
}
func fixtureControlCommand(ctx context.Context, s generated.NativeSlackFixtureScope, args ...string) *exec.Cmd {
	c := exec.CommandContext(ctx, "/usr/local/bin/vsk-labs", args...)
	c.Dir = "/"
	c.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "CREDENTIALS_DIRECTORY=" + fixtureControlCredentials}
	c.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(s.ControlServiceUID), Gid: uint32(s.ControlServiceGID), Groups: []uint32{}}, Pdeathsig: syscall.SIGKILL}
	c.WaitDelay = 3 * time.Second
	return c
}
func startFixtureControl(ctx context.Context, s generated.NativeSlackFixtureScope, setup bool) (*fixtureControlChild, error) {
	if d, e := fileDigest("/usr/local/bin/vsk-labs", 256<<20); e != nil || d != s.ExecutableDigest {
		return nil, ErrUnavailable
	}
	args := []string{"server", "run", "--config", fixtureControlProfile, "--output", "json"}
	if setup {
		args = append(args, "--setup", slackFixtureSetupPath)
	}
	c := &fixtureControlChild{cmd: fixtureControlCommand(ctx, s, args...), done: make(chan struct{})}
	c.cmd.Stdout = &c.output
	c.cmd.Stderr = io.Discard
	if e := c.cmd.Start(); e != nil {
		return nil, ErrUnavailable
	}
	go func() { c.err = c.cmd.Wait(); close(c.done) }()
	var e error
	c.start, e = fixtureStartIdentity(c.cmd.Process.Pid)
	if e != nil {
		_ = c.cmd.Process.Kill()
		<-c.done
		return nil, ErrUnavailable
	}
	return c, nil
}
func (c *fixtureControlChild) stop(sig os.Signal) error {
	select {
	case <-c.done:
		return nil
	default:
	}
	// os.Process uses a pidfd on supported Linux kernels; additionally retain
	// the measured start identity before signalling our still-owned child.
	start, e := fixtureStartIdentity(c.cmd.Process.Pid)
	if e != nil || start != c.start {
		return ErrUnavailable
	}
	if e = c.cmd.Process.Signal(sig); e != nil {
		return ErrUnavailable
	}
	select {
	case <-c.done:
		return nil
	case <-time.After(10 * time.Second):
		_ = c.cmd.Process.Kill()
		<-c.done
		return ErrUnavailable
	}
}

type fixtureControlHealth struct {
	State         string `json:"state"`
	ReadAvailable bool   `json:"readAvailable"`
	InstanceID    string `json:"instanceId"`
	RecoveryEpoch int64  `json:"recoveryEpoch"`
	SafeMode      bool   `json:"safeMode"`
	PID           int64  `json:"pid"`
	SocketDigest  string `json:"socketDigest"`
}

func fixtureReadControlHealth(ctx context.Context, s generated.NativeSlackFixtureScope) (fixtureControlHealth, error) {
	var h fixtureControlHealth
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	c := fixtureControlCommand(ctx, s, linuxrole.HandoffHealthMode)
	var out fixturePrivateOutput
	c.Stdout = &out
	c.Stderr = io.Discard
	if c.Run() != nil || json.Unmarshal(out.bytes(), &h) != nil || h.State != "ready" || !h.ReadAvailable || h.SafeMode || h.InstanceID == "" {
		return h, ErrUnavailable
	}
	return h, nil
}
func waitFixtureControl(ctx context.Context, s generated.NativeSlackFixtureScope, c *fixtureControlChild) (fixtureControlHealth, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	for {
		h, e := fixtureReadControlHealth(ctx, s)
		if e == nil && h.PID == int64(c.cmd.Process.Pid) {
			return h, nil
		}
		select {
		case <-ctx.Done():
			return h, ErrUnavailable
		case <-c.done:
			return h, ErrUnavailable
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// Include identities and bytes of every existing SQLite sidecar. A refusal is
// accepted only if the complete preimage is unchanged, including absence.
func fixtureControlPreimage() (string, error) {
	type entry struct {
		Path          string
		Device, Inode uint64
		UID, Mode     uint32
		Digest        string
	}
	var all []entry
	for _, p := range []string{fixtureControlDatabase, fixtureControlDatabase + "-wal", fixtureControlDatabase + "-shm", fixtureControlDatabase + "-journal", fixtureControlDatabase + ".lock", slackFixtureSetupPath + ".approval.json"} {
		var st unix.Stat_t
		if e := unix.Lstat(p, &st); errors.Is(e, unix.ENOENT) {
			all = append(all, entry{Path: p, Digest: "absent"})
			continue
		} else if e != nil {
			return "", ErrUnavailable
		}
		raw, uid, mode, e := fixtureRegularFile(p, 256<<20)
		if e != nil {
			return "", ErrUnavailable
		}
		all = append(all, entry{p, uint64(st.Dev), st.Ino, uid, mode, hostaction.BytesDigest(raw)})
	}
	return hostaction.Digest(all), nil
}
func fixtureRefusal(ctx context.Context, s generated.NativeSlackFixtureScope, kind string, setup bool) (generated.NativeControlSetupAttempt, error) {
	a := generated.NativeControlSetupAttempt{Schema: generated.SchemaIDNativeControlSetupAttempt, SchemaVersion: "1.0.0", Kind: kind}
	var e error
	a.BeforeDigest, e = fixtureControlPreimage()
	if e != nil {
		return a, e
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	c, e := startFixtureControl(ctx, s, setup)
	if e != nil {
		return a, e
	}
	defer c.stop(syscall.SIGKILL)
	select {
	case <-ctx.Done():
		return a, ErrUnavailable
	case <-c.done:
	}
	var out struct {
		Errors []struct {
			Code string `json:"code"`
		} `json:"errors"`
	}
	if c.err == nil || json.Unmarshal(c.output.bytes(), &out) != nil || len(out.Errors) != 1 || out.Errors[0].Code != "STATE_CONFLICT" {
		return a, ErrUnavailable
	}
	a.AfterDigest, e = fixtureControlPreimage()
	if e != nil || a.BeforeDigest != a.AfterDigest {
		return a, ErrUnavailable
	}
	a.ErrorCode = out.Errors[0].Code
	a.PID = int64(c.cmd.Process.Pid)
	a.StartIdentity = c.start
	a.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return a, nil
}

func superviseFixtureControl(ctx context.Context, s generated.NativeSlackFixtureScope, setup generated.LocalSetupRequest) error {
	if s.ControlServiceUID <= 0 || s.ControlServiceGID <= 0 || s.ControlServiceUID > 1<<32-1 || s.ControlServiceGID > 1<<32-1 || setup.ServiceUID != s.ControlServiceUID || ownedDirectory(fixtureControlCredentials, uint32(s.ControlServiceUID)) != nil || ownedDirectory("/var/lib/vsk-labs/control", uint32(s.ControlServiceUID)) != nil {
		return ErrUnavailable
	}
	for _, p := range []string{fixtureControlDatabase, fixtureControlDatabase + "-wal", fixtureControlDatabase + "-shm", fixtureControlDatabase + "-journal", fixtureControlDatabase + ".lock", slackFixtureSetupPath + ".approval.json", fixtureSetupWitnessPath} {
		if _, e := os.Lstat(p); !errors.Is(e, os.ErrNotExist) {
			return ErrUnavailable
		}
	}
	w := generated.NativeControlSetupWitness{Schema: generated.SchemaIDNativeControlSetupWitness, SchemaVersion: "1.0.0", ScopeDigest: hostaction.Digest(s), FixtureScope: s, PeerPID: int64(os.Getpid()), SetupID: setup.SetupID, SetupRequestDigest: s.SetupRequestDigest, SetupReviewDigest: s.SetupPlanDigest, InitialProfileDigest: setup.ProfileSHA256}
	var e error
	w.PeerStartIdentity, e = fixtureStartIdentity(os.Getpid())
	if e != nil {
		return ErrUnavailable
	}
	// Create only the absent, owned incomplete fixture. On any unexpected result
	// preserve it for diagnosis rather than deleting an unknown or changed file.
	f, e := os.OpenFile(fixtureControlDatabase+".lock", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return ErrUnavailable
	}
	if e = f.Chown(int(s.ControlServiceUID), int(s.ControlServiceGID)); e != nil {
		f.Close()
		return ErrUnavailable
	}
	incompleteInfo, e := f.Stat()
	f.Close()
	if e != nil {
		return ErrUnavailable
	}
	a, e := fixtureRefusal(ctx, s, "incomplete-refusal", true)
	if e != nil {
		return e
	}
	w.Attempts = append(w.Attempts, a)
	currentIncomplete, e := os.Lstat(fixtureControlDatabase + ".lock")
	if e != nil || !os.SameFile(incompleteInfo, currentIncomplete) {
		return ErrUnavailable
	}
	if e = os.Remove(fixtureControlDatabase + ".lock"); e != nil {
		return ErrUnavailable
	}
	before, e := fixtureControlPreimage()
	if e != nil {
		return e
	}
	c, e := startFixtureControl(ctx, s, true)
	if e != nil {
		return e
	}
	defer func() {
		if c != nil {
			_ = c.stop(syscall.SIGTERM)
		}
	}()
	h, e := waitFixtureControl(ctx, s, c)
	if e != nil {
		return e
	}
	w.InstanceID = h.InstanceID
	w.RecoveryEpoch = h.RecoveryEpoch
	w.InitialPID = h.PID
	w.InitialStartIdentity = c.start
	after, e := fixtureControlPreimage()
	if e != nil {
		return e
	}
	w.Attempts = append(w.Attempts, generated.NativeControlSetupAttempt{Schema: generated.SchemaIDNativeControlSetupAttempt, SchemaVersion: "1.0.0", Kind: "fresh", BeforeDigest: before, AfterDigest: after, InstanceID: h.InstanceID, PID: h.PID, StartIdentity: c.start, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)})
	for _, kind := range []string{"populated-refusal", "writer-refusal"} {
		a, e = fixtureRefusal(ctx, s, kind, kind == "populated-refusal")
		if e != nil {
			return e
		}
		a.InstanceID = h.InstanceID
		w.Attempts = append(w.Attempts, a)
	}
	for _, kind := range []string{"restart", "crash-restart"} {
		before, e = fixtureControlPreimage()
		if e != nil {
			return e
		}
		sig := syscall.SIGTERM
		if kind == "crash-restart" {
			sig = syscall.SIGKILL
		}
		if e = c.stop(sig); e != nil {
			return e
		}
		c, e = startFixtureControl(ctx, s, false)
		if e != nil {
			return e
		}
		next, err := waitFixtureControl(ctx, s, c)
		if err != nil || next.InstanceID != h.InstanceID || next.RecoveryEpoch != h.RecoveryEpoch {
			return ErrUnavailable
		}
		after, e = fixtureControlPreimage()
		if e != nil {
			return e
		}
		w.Attempts = append(w.Attempts, generated.NativeControlSetupAttempt{Schema: generated.SchemaIDNativeControlSetupAttempt, SchemaVersion: "1.0.0", Kind: kind, BeforeDigest: before, AfterDigest: after, InstanceID: next.InstanceID, PID: next.PID, StartIdentity: c.start, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)})
	}
	// Initial setup deliberately has no signer. Activate only the protected
	// prepared signer and optional existing backup backend after measuring
	// every setup/refusal/restart case.
	before, e = fixtureControlPreimage()
	if e != nil || c.stop(syscall.SIGTERM) != nil {
		return ErrUnavailable
	}
	w.FinalProfileDigest, e = replaceFixtureSignerProfile(fixtureControlProfile, fixtureControlFinalProfile, uint32(s.ControlServiceUID), uint32(s.ControlServiceGID), setup.ProfileSHA256)
	if e != nil {
		return e
	}
	c, e = startFixtureControl(ctx, s, false)
	if e != nil {
		return e
	}
	next, err := waitFixtureControl(ctx, s, c)
	if err != nil || next.InstanceID != h.InstanceID || next.RecoveryEpoch != h.RecoveryEpoch {
		return ErrUnavailable
	}
	after, e = fixtureControlPreimage()
	if e != nil {
		return e
	}
	w.Attempts = append(w.Attempts, generated.NativeControlSetupAttempt{Schema: generated.SchemaIDNativeControlSetupAttempt, SchemaVersion: "1.0.0", Kind: "signer-restart", BeforeDigest: before, AfterDigest: after, InstanceID: next.InstanceID, PID: next.PID, StartIdentity: c.start, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)})
	receipt, uid, mode, e := fixtureRegularFile(slackFixtureSetupPath+".approval.json", 65536)
	if e != nil || int64(uid) != s.ControlServiceUID || mode != 0600 {
		return ErrUnavailable
	}
	var approval struct {
		Review   json.RawMessage                              `json:"review"`
		Approval struct{ ReviewDigest, RequestDigest string } `json:"approval"`
	}
	if json.Unmarshal(receipt, &approval) != nil || hostaction.BytesDigest(approval.Review) != s.SetupPlanDigest || approval.Approval.ReviewDigest != s.SetupPlanDigest || approval.Approval.RequestDigest != s.SetupRequestDigest {
		return ErrUnavailable
	}
	if !fixtureSetupProfileMatches(approval.Review, w.InitialProfileDigest) {
		return ErrUnavailable
	}
	w.ApprovalDigest = hostaction.BytesDigest(receipt)
	w.FinalPID = int64(c.cmd.Process.Pid)
	w.FinalStartIdentity = c.start
	w.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
	raw, e := json.Marshal(w)
	if e != nil || generated.ValidateContractJSON(generated.SchemaIDNativeControlSetupWitness, raw, generated.ContractExact) != nil {
		return ErrUnavailable
	}
	f, e = os.OpenFile(fixtureSetupWitnessPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return ErrUnavailable
	}
	_, e = f.Write(raw)
	if e == nil {
		e = f.Sync()
	}
	f.Close()
	if e != nil {
		return ErrUnavailable
	}
	// Only the real handoff may naturally terminate this predecessor. The TLS
	// fixture continues until its original scope expires; no automatic restart.
	select {
	case <-ctx.Done():
		return nil
	case <-c.done:
		deadline := time.NewTimer(45 * time.Second)
		defer deadline.Stop()
		for {
			if _, e = linuxrole.InspectNativeControlHandoff(ctx); e == nil {
				break
			}
			select {
			case <-ctx.Done():
				return ErrUnavailable
			case <-deadline.C:
				return ErrUnavailable
			case <-time.After(200 * time.Millisecond):
			}
		}
		<-ctx.Done()
		return nil
	}
}

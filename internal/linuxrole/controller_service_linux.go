//go:build linux

package linuxrole

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"golang.org/x/sys/unix"
)

const controllerPilotJournal = "var/lib/vsk-labs/access-rollback/controller-pilot-handoff.json"

type controllerCustodyFile struct {
	Path     string
	Metadata controllerMetadata
}

func controllerServiceCustody(in ControllerInstallInput) ([]controllerCustodyFile, error) {
	paths := []string{"/var/lib/vsk-labs/control", "/run/vsk-labs-control", "/var/lib/vsk-labs/control/exports", controlConfig, "/etc/vsk-labs/control/slack.json", controlDatabase, controlDatabase + ".lock", controlSocket + ".lock", ControllerRecoveryImage}
	for _, p := range []string{controlDatabase + "-wal", controlDatabase + "-shm", controlSocket} {
		if _, e := os.Lstat(p); e == nil {
			paths = append(paths, p)
		} else if !os.IsNotExist(e) {
			return nil, errNative
		}
	}
	entries, e := os.ReadDir("/var/lib/vsk-labs/control/exports")
	if e != nil || len(entries) > 256 {
		return nil, errNative
	}
	for _, entry := range entries {
		if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`).MatchString(entry.Name()) || entry.IsDir() {
			return nil, errNative
		}
		paths = append(paths, "/var/lib/vsk-labs/control/exports/"+entry.Name())
	}
	facts := []controllerCustodyFile{}
	for _, p := range paths {
		if controllerServiceAncestors(p, in.AdministratorUID) != nil {
			return nil, errNative
		}
		var s unix.Stat_t
		if unix.Lstat(p, &s) != nil || s.Uid != uint32(in.AdministratorUID) || s.Mode&0022 != 0 {
			return nil, errNative
		}
		kind := s.Mode & unix.S_IFMT
		if kind != unix.S_IFREG && kind != unix.S_IFDIR && !(p == controlSocket && kind == unix.S_IFSOCK) {
			return nil, errNative
		}
		if kind == unix.S_IFREG && s.Nlink != 1 {
			return nil, errNative
		}
		facts = append(facts, controllerCustodyFile{p, metadataOf(s)})
	}
	return facts, nil
}

func controllerServiceAncestors(p string, uid int64) error {
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	for i := 0; i < len(parts)-1; i++ {
		prefix := "/" + strings.Join(parts[:i+1], "/")
		var s unix.Stat_t
		if unix.Lstat(prefix, &s) != nil || s.Mode&unix.S_IFMT != unix.S_IFDIR || s.Mode&0022 != 0 {
			return errNative
		}
		selected := prefix == "/etc/vsk-labs/control" || prefix == "/var/lib/vsk-labs/control" || prefix == "/var/lib/vsk-labs/control/exports" || prefix == "/run/vsk-labs-control"
		if s.Uid != 0 && (!selected || int64(s.Uid) != uid) {
			return errNative
		}
	}
	return nil
}

func ObserveControllerServiceCustody(in ControllerInstallInput) (string, error) {
	if ValidateControllerInstallInput(in) != nil || in.Stage != ControllerHandoffStage {
		return "", errInput
	}
	facts, e := controllerServiceCustody(in)
	if e != nil {
		return "", e
	}
	return hostaction.Digest(facts), nil
}

func controllerPilotHealth(ctx context.Context, in ControllerInstallInput) (controlHealth, error) {
	var health controlHealth
	b, _ := json.Marshal(in)
	c := exec.CommandContext(ctx, "/usr/local/bin/vsk-labs", "controller-pilot-health")
	c.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	c.Dir = "/"
	c.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(in.AdministratorUID), Gid: uint32(in.AdministratorGID), Groups: []uint32{}}}
	c.Stdin = bytes.NewReader(b)
	var out boundedOutput
	c.Stdout = &out
	if c.Run() != nil || json.Unmarshal(out.Bytes(), &health) != nil {
		return health, errNative
	}
	return health, nil
}

func controllerHandoffPreconditions(ctx context.Context, in ControllerInstallInput) error {
	if in.Stage != ControllerHandoffStage || in.Handoff == nil {
		return errInput
	}
	expires, e := time.Parse(time.RFC3339, in.Handoff.ExpiresAt)
	if e != nil || !time.Now().Before(expires) {
		return errNative
	}
	credentialDigest, e := ObserveControllerCredentialCustody(in)
	if e != nil || credentialDigest != in.CredentialCustodyDigest {
		return errNative
	}
	if _, e = verifyControllerFoundation(ctx, in); e != nil {
		return e
	}
	config, e := ownedFile(controlConfig, in.AdministratorUID, 65536)
	if e != nil {
		return e
	}
	if _, e = ControllerServiceConfig(in, config); e != nil {
		return e
	}
	digest, e := ObserveControllerServiceCustody(in)
	if e != nil || digest != in.Handoff.CustodyDigest {
		return errNative
	}
	start, e := processStart(in.Handoff.ForegroundPID)
	if e != nil || start != in.Handoff.ForegroundStartIdentity {
		return errNative
	}
	var s unix.Stat_t
	if unix.Stat("/proc/"+strconv.FormatInt(in.Handoff.ForegroundPID, 10), &s) != nil || s.Uid != uint32(in.AdministratorUID) {
		return errNative
	}
	exe, e := readProcessExecutable(in.Handoff.ForegroundPID)
	if e != nil || hostaction.BytesDigest(exe) != in.Handoff.ForegroundExecutableDigest {
		return errNative
	}
	pid, socket, e := controllerSocketPeer(ctx, uint32(in.AdministratorUID), 0600)
	if e != nil || pid != in.Handoff.ForegroundPID || socket != in.Handoff.SocketIdentityDigest {
		return errNative
	}
	if os.Geteuid() == 0 {
		health, e := readControlHealth(ctx, in.AdministratorUID, in.AdministratorGID)
		if e != nil || health.PID != in.Handoff.ForegroundPID || health.InstanceID != in.ControllerInstanceID || health.RecoveryEpoch != in.RecoveryEpoch || health.State != "ready" || !health.ReadAvailable || health.SocketDigest != in.Handoff.SocketIdentityDigest {
			return errNative
		}
	}
	return nil
}

func installControllerService(ctx context.Context, in ControllerInstallInput, version string) (changed bool, err error) {
	if os.Getuid() != 0 || os.Geteuid() != 0 || ValidateControllerInstallInput(in) != nil || in.Stage != ControllerHandoffStage {
		return false, errNative
	}
	n := NewNativeRuntime(version).(*nativeRuntime)
	expires, e := time.Parse(time.RFC3339, in.Handoff.ExpiresAt)
	if e != nil {
		return false, errNative
	}
	ctx, cancel := context.WithDeadline(ctx, expires)
	defer cancel()
	err = n.withLock(ctx, func() error {
		if e := controllerHandoffPreconditions(ctx, in); e != nil {
			return e
		}
		if _, e := readProtected(n.root, controllerPilotJournal, 1<<20); e == nil || !os.IsNotExist(e) {
			return errNative
		}
		before, e := ownedFile(controlConfig, in.AdministratorUID, 65536)
		if e != nil {
			return e
		}
		after, e := ControllerServiceConfig(in, before)
		if e != nil {
			return e
		}
		custody, e := controllerServiceCustody(in)
		if e != nil || hostaction.Digest(custody) != in.Handoff.CustodyDigest {
			return errNative
		}
		lockDigest, lock, e := lockIdentity(in.AdministratorUID)
		if e != nil {
			return e
		}
		defer lock.Close()
		if lockDigest != in.Handoff.WriterLockDigest || !processOwnsWriter(in.Handoff.ForegroundPID, lock) {
			return errNative
		}
		if unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB) == nil {
			unix.Flock(int(lock.Fd()), unix.LOCK_UN)
			return errNative
		}
		stop, closePID, e := n.prepareStop(&generated.ControlHandoffInput{ForegroundPID: in.Handoff.ForegroundPID, ForegroundStartIdentity: in.Handoff.ForegroundStartIdentity})
		if e != nil {
			return e
		}
		defer closePID()
		journal := struct {
			Input        ControllerInstallInput
			BeforeConfig []byte
			Custody      []controllerCustodyFile
			Status       string
		}{in, before, custody, "stopping"}
		save := func(status string) error {
			journal.Status = status
			b, e := json.Marshal(journal)
			if e != nil {
				return e
			}
			return writeControllerArtifact(ctx, n.root, controllerPilotJournal, b, 0600, 0, false)
		}
		if e = save("stopping"); e != nil {
			return e
		}
		changed = true
		fail := func() error { _ = save("recovery-required"); return errNative }
		if e = stop(ctx); e != nil {
			return fail()
		}
		// Keep the exact original writer lock held through every custody change.
		// An old supervisor cannot acquire a second writer during the transition.
		if unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
			return fail()
		}
		defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
		// The acknowledged handoff has stopped the administrator writer and
		// holds its exact lock. Only now may root take the declared credential
		// custody; Slack remains available for requesting this handoff first.
		if _, e = moveControllerCredentialCustody(ctx, in); e != nil {
			return fail()
		}
		for _, entry := range custody {
			p := entry.Path
			var st unix.Stat_t
			if unix.Lstat(p, &st) != nil {
				if (p == controlSocket || p == controlDatabase+"-wal" || p == controlDatabase+"-shm") && os.IsNotExist(func() error { _, e := os.Lstat(p); return e }()) {
					continue
				}
				return fail()
			}
			if metadataOf(st) != entry.Metadata {
				return fail()
			}
			if p == controlSocket {
				if os.Remove(p) != nil {
					return fail()
				}
				continue
			}
			fd, e := unix.Openat2(unix.AT_FDCWD, p, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
			if e != nil {
				return fail()
			}
			var opened unix.Stat_t
			if unix.Fstat(fd, &opened) != nil || metadataOf(opened) != entry.Metadata {
				unix.Close(fd)
				return fail()
			}
			gid := int(in.ServiceGID)
			mode := opened.Mode & 0777
			if p == controlConfig {
				gid = int(in.AdministratorGID)
				mode = 0640
			}
			if p == "/run/vsk-labs-control" {
				mode = 0750
			}
			e = unix.Fchown(fd, int(in.ServiceUID), gid)
			if e == nil {
				e = unix.Fchmod(fd, mode)
			}
			if e == nil {
				e = unix.Fsync(fd)
			}
			unix.Close(fd)
			if e != nil {
				return fail()
			}
		}
		// The parent is root-owned after the credential custody transfer; replace only the
		// exact acknowledged config, preserving every unrelated JSON declaration.
		currentConfig, e := ownedFile(controlConfig, in.ServiceUID, 65536)
		if e != nil || hostaction.BytesDigest(currentConfig) != in.ConfigDigest {
			return fail()
		}
		currentSlack, e := ownedFile("/etc/vsk-labs/control/slack.json", in.ServiceUID, 32768)
		if e != nil || hostaction.BytesDigest(currentSlack) != in.SlackProfileDigest {
			return fail()
		}
		if e = writeControllerArtifact(ctx, n.root, "etc/vsk-labs/control/server.json", after, 0640, int(in.AdministratorGID), false); e != nil {
			return fail()
		}
		if e = os.Chown(controlConfig, int(in.ServiceUID), int(in.AdministratorGID)); e != nil {
			return fail()
		}
		if e = save("starting"); e != nil {
			return fail()
		}
		if unix.Flock(int(lock.Fd()), unix.LOCK_UN) != nil {
			return fail()
		}
		for _, verb := range []string{"daemon-reload", "enable", "start"} {
			args := []string{verb}
			if verb != "daemon-reload" {
				args = append(args, "vsk-labs.service")
			}
			if _, e = n.run(ctx, "/usr/bin/systemctl", args); e != nil {
				return fail()
			}
		}
		for ctx.Err() == nil {
			h, e := controllerPilotHealth(ctx, in)
			if e == nil && h.InstanceID == in.ControllerInstanceID && h.RecoveryEpoch == in.RecoveryEpoch && h.State == "ready" && h.ReadAvailable && h.PID > 1 && h.PID != in.Handoff.ForegroundPID {
				return save("completed")
			}
			select {
			case <-ctx.Done():
				return fail()
			case <-time.After(100 * time.Millisecond):
			}
		}
		return fail()
	})
	return changed, err
}

func verifyControllerService(ctx context.Context, in ControllerInstallInput) (string, error) {
	pid, socket, e := controllerSocketPeer(ctx, uint32(in.ServiceUID), 0660)
	if e != nil {
		return "", e
	}
	config, e := ownedFile(controlConfig, in.ServiceUID, 65536)
	if e != nil {
		return "", e
	}
	want := in.ConfigDigest
	if in.Handoff != nil {
		want = in.Handoff.DesiredConfigDigest
	}
	if hostaction.BytesDigest(config) != want {
		return "", errNative
	}
	raw, e := roleCommand(ctx, "/usr/bin/systemctl", []string{"show", "vsk-labs.service", "--property=ActiveState,MainPID,User,FragmentPath,DropInPaths", "--no-pager"})
	if e != nil {
		return "", e
	}
	p := parseProperties(raw)
	if p["ActiveState"] != "active" || p["User"] != strconv.FormatInt(in.ServiceUID, 10) || p["MainPID"] != strconv.FormatInt(pid, 10) || p["FragmentPath"] != "/etc/systemd/system/vsk-labs.service" || p["DropInPaths"] != "" {
		return "", errNative
	}
	exe, e := readProcessExecutable(pid)
	if e != nil || hostaction.BytesDigest(exe) != in.ExecutableDigest {
		return "", errNative
	}
	start, e := processStart(pid)
	if e != nil {
		return "", e
	}
	return hostaction.Digest(map[string]any{"stage": "service-running-awaiting-native-verification", "pid": pid, "start": start, "socket": socket, "config": want, "input": hostaction.Digest(in)}), nil
}

func controllerSocketPeer(ctx context.Context, uid, mode uint32) (int64, string, error) {
	var before unix.Stat_t
	if unix.Lstat(controlSocket, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFSOCK || before.Uid != uid || before.Mode&0777 != mode {
		return 0, "", errNative
	}
	c, e := (&net.Dialer{}).DialContext(ctx, "unix", controlSocket)
	if e != nil {
		return 0, "", errNative
	}
	defer c.Close()
	u, ok := c.(*net.UnixConn)
	if !ok {
		return 0, "", errNative
	}
	sc, e := u.SyscallConn()
	if e != nil {
		return 0, "", errNative
	}
	var cred *unix.Ucred
	var ce error
	if sc.Control(func(fd uintptr) { cred, ce = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }) != nil || ce != nil || cred == nil || cred.Uid != uid || cred.Pid <= 1 {
		return 0, "", errNative
	}
	var after unix.Stat_t
	if unix.Lstat(controlSocket, &after) != nil || after.Dev != before.Dev || after.Ino != before.Ino || after.Uid != before.Uid || after.Mode != before.Mode {
		return 0, "", errNative
	}
	return int64(cred.Pid), hostaction.Digest(map[string]any{"path": controlSocket, "uid": before.Uid, "mode": before.Mode & 0777}), nil
}

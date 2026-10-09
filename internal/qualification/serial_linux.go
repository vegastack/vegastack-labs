//go:build linux

package qualification

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

func ownedSocket(ctx context.Context, path string, pid int) (net.Conn, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0077 != 0 {
		return nil, ErrUnavailable
	}
	uid, ok := fileOwner(info)
	if !ok || uid != uint32(os.Geteuid()) {
		return nil, ErrUnavailable
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	deny := func() (net.Conn, error) { conn.Close(); return nil, ErrUnavailable }
	u, ok := conn.(*net.UnixConn)
	if !ok {
		return deny()
	}
	raw, err := u.SyscallConn()
	if err != nil {
		return deny()
	}
	var peer *unix.Ucred
	var peerErr error
	if raw.Control(func(fd uintptr) { peer, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }) != nil || peerErr != nil || peer == nil || peer.Pid != int32(pid) || peer.Uid != uint32(os.Geteuid()) {
		return deny()
	}
	return conn, nil
}

var bootIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func (d *ownedGuestLifecycle) consoleBootID(ctx context.Context, id string) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.checkProcess(id); err != nil {
		return "", err
	}
	conn, err := ownedSocket(ctx, filepath.Join(d.scope.value.OutputRoot, id+".serial"), int(d.launches[id].QEMUPID))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	deadline := time.Now().Add(10 * time.Second)
	if v, ok := ctx.Deadline(); ok && v.Before(deadline) {
		deadline = v
	}
	if conn.SetDeadline(deadline) != nil {
		return "", ErrUnavailable
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if err := d.authenticateConsole(conn); err != nil {
		return "", err
	}
	nonce := make([]byte, 16)
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}
	marker := "VSKBOOT" + hex.EncodeToString(nonce)
	// The fixed command contains only a cryptographically generated hex marker.
	// A login prompt, echoed command, stale console text or malformed UUID fails.
	command := "\x15printf '\\n" + marker + "\\n'; /usr/bin/cat /proc/sys/kernel/random/boot_id; printf '" + marker + "END\\n'\n"
	if _, err = io.WriteString(conn, command); err != nil {
		return "", err
	}
	scanner := bufio.NewScanner(io.LimitReader(conn, 32769))
	scanner.Buffer(make([]byte, 1024), 4096)
	started := false
	boot := ""
	count := 0
	for scanner.Scan() {
		count += len(scanner.Bytes()) + 1
		if count > 32768 {
			return "", ErrUnavailable
		}
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if !started {
			if line == marker {
				started = true
			}
			continue
		}
		if boot == "" {
			if !bootIDPattern.MatchString(line) || line == "00000000-0000-0000-0000-000000000000" {
				return "", ErrUnavailable
			}
			boot = line
			continue
		}
		if line == marker+"END" {
			if d.checkProcess(id) != nil {
				return "", ErrUnavailable
			}
			return boot, nil
		}
		return "", ErrUnavailable
	}
	return "", ErrUnavailable
}

// authenticateConsole handles only the fixed disposable root console. The
// fixture password is never part of a scope, command argument or transcript.
func (d *ownedGuestLifecycle) authenticateConsole(conn net.Conn) error {
	if _, err := io.WriteString(conn, "\n"); err != nil {
		return err
	}
	var transcript strings.Builder
	sentUser, sentPassword := false, false
	one := make([]byte, 1)
	for i := 0; i < 16384; i++ {
		if _, err := io.ReadFull(conn, one); err != nil {
			return ErrUnavailable
		}
		transcript.WriteByte(one[0])
		tail := transcript.String()
		if strings.HasSuffix(tail, "login: ") && !sentUser {
			if _, err := io.WriteString(conn, "root\n"); err != nil {
				return err
			}
			sentUser = true
			transcript.Reset()
			continue
		}
		if strings.HasSuffix(tail, "Password: ") && sentUser && !sentPassword {
			secret, err := ownedFile(filepath.Join(d.scope.value.OutputRoot, "console.secret"), uint32(os.Geteuid()), 256)
			if err != nil {
				return ErrUnavailable
			}
			secret = []byte(strings.TrimSuffix(string(secret), "\n"))
			if len(secret) < 16 || len(secret) > 128 || strings.ContainsAny(string(secret), "\r\n\x00") {
				for j := range secret {
					secret[j] = 0
				}
				return ErrUnavailable
			}
			_, err = conn.Write(append(secret, '\n'))
			for j := range secret {
				secret[j] = 0
			}
			if err != nil {
				return err
			}
			sentPassword = true
			transcript.Reset()
			continue
		}
		if strings.HasSuffix(tail, "# ") {
			return nil
		}
		if strings.Contains(tail, "Login incorrect") {
			return ErrUnavailable
		}
	}
	return ErrUnavailable
}

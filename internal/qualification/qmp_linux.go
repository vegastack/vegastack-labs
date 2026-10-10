//go:build linux

package qualification

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// qmpCommand permits only finite fixture lifecycle requests. No callers can
// supply arbitrary QMP names or arguments.
type qmpCommand uint8

const (
	qmpStatus qmpCommand = iota
	qmpPowerdown
	qmpQuit
)

func ownedQMP(ctx context.Context, path string, pid int, command qmpCommand) (string, error) {
	names := []string{"query-status", "system_powerdown", "quit"}
	if command > qmpQuit || ctx == nil || ctx.Err() != nil {
		return "", ErrUnavailable
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0077 != 0 {
		return "", ErrUnavailable
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	socket, ok := conn.(*net.UnixConn)
	if !ok {
		return "", ErrUnavailable
	}
	raw, err := socket.SyscallConn()
	if err != nil {
		return "", err
	}
	var peer *unix.Ucred
	var peerErr error
	if err = raw.Control(func(fd uintptr) { peer, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil || peerErr != nil || peer.Pid != int32(pid) || peer.Uid != uint32(os.Geteuid()) {
		return "", ErrUnavailable
	}
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err = conn.SetDeadline(deadline); err != nil {
		return "", err
	}
	reader := bufio.NewReader(io.LimitReader(conn, 65536))
	read := func() (map[string]json.RawMessage, error) {
		line, e := reader.ReadBytes('\n')
		if e != nil || len(line) > 16384 {
			return nil, ErrUnavailable
		}
		var v map[string]json.RawMessage
		if json.Unmarshal(line, &v) != nil {
			return nil, ErrUnavailable
		}
		return v, nil
	}
	greeting, err := read()
	if err != nil || len(greeting["QMP"]) == 0 {
		return "", ErrUnavailable
	}
	write := func(name, id string) error {
		return json.NewEncoder(conn).Encode(struct {
			Execute string `json:"execute"`
			ID      string `json:"id"`
		}{name, id})
	}
	reply := func(id string) (json.RawMessage, error) {
		for i := 0; i < 16; i++ {
			v, e := read()
			if e != nil {
				return nil, e
			}
			if len(v["event"]) > 0 {
				continue
			}
			var got string
			if json.Unmarshal(v["id"], &got) != nil || got != id || len(v["error"]) > 0 || len(v["return"]) == 0 {
				return nil, ErrUnavailable
			}
			return v["return"], nil
		}
		return nil, ErrUnavailable
	}
	if write("qmp_capabilities", "capabilities") != nil {
		return "", ErrUnavailable
	}
	if _, err = reply("capabilities"); err != nil {
		return "", err
	}
	if write(names[command], "operation") != nil {
		return "", ErrUnavailable
	}
	body, err := reply("operation")
	if err != nil {
		return "", err
	}
	if command != qmpStatus {
		return "", nil
	}
	var status struct {
		Status  string `json:"status"`
		Running bool   `json:"running"`
	}
	if json.Unmarshal(body, &status) != nil {
		return "", ErrUnavailable
	}
	if status.Running && status.Status == "running" {
		return "running", nil
	}
	if !status.Running && (status.Status == "shutdown" || status.Status == "paused" || status.Status == "prelaunch") {
		return status.Status, nil
	}
	return "", ErrUnavailable
}

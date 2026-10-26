//go:build linux

package hostingplatform

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type nativeRuntime struct {
	root string
	run  func(context.Context, string, []string) ([]byte, error)
}

func NewNativeRuntime() Runtime { return &nativeRuntime{run: runCommand} }
func runCommand(ctx context.Context, bin string, args []string) ([]byte, error) {
	if bin != "/usr/bin/docker" && bin != "/usr/bin/systemctl" {
		return nil, denied()
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	c := exec.CommandContext(ctx, bin, args...)
	c.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "HOME=/root"}
	c.Dir = "/"
	c.Stderr = io.Discard
	var out bytes.Buffer
	c.Stdout = &boundedBuffer{&out}
	if c.Run() != nil {
		return nil, denied()
	}
	return out.Bytes(), nil
}

type boundedBuffer struct{ b *bytes.Buffer }

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.b.Len()+len(p) > 1<<20 {
		return 0, denied()
	}
	return b.b.Write(p)
}
func bytesDigest(b []byte) string { s := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(s[:]) }
func protected(path string, max int64) ([]byte, os.FileInfo, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, nil, denied()
	}
	cur := "/"
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		cur = filepath.Join(cur, part)
		s, e := os.Lstat(cur)
		if e != nil || s.Mode()&os.ModeSymlink != 0 || s.Mode().Perm()&0022 != 0 {
			return nil, nil, denied()
		}
		st, ok := s.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 {
			return nil, nil, denied()
		}
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, nil, denied()
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || (max > 0 && st.Size() > max) {
		return nil, nil, denied()
	}
	if max == 0 {
		return nil, st, nil
	}
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || int64(len(b)) > max {
		return nil, nil, denied()
	}
	return b, st, nil
}

type composeService struct {
	Environment  map[string]string `json:"environment"`
	IPC          string            `json:"ipc"`
	UserNS       string            `json:"userns_mode"`
	CapAdd       []string          `json:"cap_add"`
	Devices      []any             `json:"devices"`
	DeviceRules  []any             `json:"device_cgroup_rules"`
	VolumesFrom  []string          `json:"volumes_from"`
	CgroupParent string            `json:"cgroup_parent"`
	Image        string            `json:"image"`
	Privileged   bool              `json:"privileged"`
	NetworkMode  string            `json:"network_mode"`
	PID          string            `json:"pid"`
	Build        json.RawMessage   `json:"build"`
	Ports        []struct {
		Target    uint16 `json:"target"`
		Published string `json:"published"`
		HostIP    string `json:"host_ip"`
	} `json:"ports"`
	Volumes []struct {
		Type   string `json:"type"`
		Source string `json:"source"`
	} `json:"volumes"`
}

func validateCompose(raw []byte, in Input) error {
	var c struct {
		Services map[string]composeService `json:"services"`
	}
	if json.Unmarshal(raw, &c) != nil || len(c.Services) != 4 {
		return denied()
	}
	for _, name := range []string{"coolify", "postgres", "redis", "soketi"} {
		s, ok := c.Services[name]
		if !ok || !strings.Contains(s.Image, "@sha256:") || len(strings.Split(s.Image, "@sha256:")) != 2 || len(strings.Split(s.Image, "@sha256:")[1]) != 64 || s.Privileged || s.NetworkMode == "host" || s.PID == "host" || s.IPC == "host" || s.UserNS == "host" || len(s.CapAdd) > 0 || len(s.Devices) > 0 || len(s.DeviceRules) > 0 || len(s.VolumesFrom) > 0 || s.CgroupParent != "" || len(s.Build) > 0 {
			return denied()
		}
		if name == "coolify" && !strings.HasPrefix(s.Image, "docker.io/coollabsio/coolify:4.3.10@sha256:") && !strings.HasPrefix(s.Image, "coollabsio/coolify:4.3.10@sha256:") {
			return denied()
		}
		for _, v := range s.Volumes {
			if v.Type != "bind" || !strings.HasPrefix(filepath.Clean(v.Source), in.ComponentDirectory+"/") {
				return denied()
			}
		}
		for _, p := range s.Ports {
			if p.HostIP != in.PrivateAddress {
				return denied()
			}
		}
		if name == "coolify" {
			if s.Environment["AUTOUPDATE"] != "false" {
				return denied()
			}
			found := false
			for _, p := range s.Ports {
				if p.Target == 8080 && p.Published == portString(in.ManagementPort) {
					found = true
				}
			}
			if !found {
				return denied()
			}
		}
	}
	return nil
}
func portString(p uint16) string {
	const digits = "0123456789"
	if p == 0 {
		return "0"
	}
	b := []byte{}
	for p > 0 {
		b = append([]byte{digits[p%10]}, b...)
		p /= 10
	}
	return string(b)
}
func (n *nativeRuntime) Execute(ctx context.Context, action string, in Input) (out Result, err error) {
	ip := net.ParseIP(in.PrivateAddress)
	if n == nil || n.run == nil || ctx == nil || ctx.Err() != nil || !IsAction(action) || in.HostID == "" || len(in.HostIdentityDigest) != 71 || in.ComponentDirectory != "/data/coolify" || ip == nil || (!ip.IsPrivate() && !ip.IsLoopback()) || in.ManagementPort == 0 {
		return out, denied()
	}
	compose, _, e := n.read(in.ComponentDirectory+"/compose.yaml", 1<<20)
	if e != nil || bytesDigest(compose) != in.ComposeDigest {
		return out, denied()
	}
	env, _, e := n.read(in.ComponentDirectory+"/environment", 65536)
	if e != nil || bytesDigest(env) != in.EnvironmentDigest || !bytes.Contains(env, []byte("AUTOUPDATE=false")) {
		return out, denied()
	}
	defer func() {
		for i := range env {
			env[i] = 0
		}
	}()
	unit, _, e := n.read("/etc/systemd/system/vsk-labs.service", 65536)
	if e != nil || bytesDigest(unit) != in.ControllerUnitDigest {
		return out, denied()
	}
	_, db, e := n.read(in.ControllerDatabasePath, 0)
	if e != nil || strings.HasPrefix(in.ControllerDatabasePath, in.ComponentDirectory+"/") {
		return out, denied()
	}
	controller := func() error {
		now, _, e := n.read("/etc/systemd/system/vsk-labs.service", 65536)
		if e != nil || bytesDigest(now) != in.ControllerUnitDigest {
			return denied()
		}
		_, current, e := n.read(in.ControllerDatabasePath, 0)
		if e != nil || !os.SameFile(db, current) {
			return denied()
		}
		b, e := n.run(ctx, "/usr/bin/systemctl", []string{"is-active", "vsk-labs.service"})
		if e != nil || strings.TrimSpace(string(b)) != "active" {
			return denied()
		}
		return nil
	}
	if controller() != nil {
		return out, denied()
	}
	args := []string{"compose", "--project-directory", in.ComponentDirectory, "--project-name", "vsk-coolify", "--file", in.ComponentDirectory + "/compose.yaml", "--env-file", in.ComponentDirectory + "/environment"}
	config, e := n.run(ctx, "/usr/bin/docker", append(append([]string{}, args...), "config", "--format", "json"))
	if e != nil || validateCompose(config, in) != nil {
		return out, denied()
	}
	defer func() {
		for i := range config {
			config[i] = 0
		}
	}()
	defer func() {
		if out.Changed && controller() != nil {
			err = denied()
		}
	}()
	if action == InstallAction {
		existing, e := n.run(ctx, "/usr/bin/docker", append(append([]string{}, args...), "ps", "--format", "json", "--all"))
		if e != nil {
			return out, denied()
		}
		if clean := strings.TrimSpace(string(existing)); clean != "" && clean != "[]" {
			return out, denied()
		}
		for _, name := range []string{"postgres", "redis", "applications", "databases", "services", "backups", "images"} {
			dir := filepath.Join(in.ComponentDirectory, name)
			if n.root != "" && n.root != "/" {
				dir = filepath.Join(n.root, strings.TrimPrefix(dir, "/"))
			}
			st, e := os.Lstat(dir)
			if os.IsNotExist(e) {
				continue
			}
			if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
				return out, denied()
			}
			entries, e := os.ReadDir(dir)
			if e != nil || len(entries) != 0 {
				return out, denied()
			}
		}
		out.Changed = true
		if _, e = n.run(ctx, "/usr/bin/docker", append(append([]string{}, args...), "up", "--detach", "--wait", "--wait-timeout", "40", "--no-build", "--pull", "never")); e != nil {
			_ = controller()
			return out, denied()
		}
	}
	b, e := n.run(ctx, "/usr/bin/docker", append(append([]string{}, args...), "ps", "--format", "json", "--all"))
	if e != nil {
		return out, denied()
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	var rendered struct {
		Services map[string]composeService `json:"services"`
	}
	if json.Unmarshal(config, &rendered) != nil {
		return out, denied()
	}
	seen := map[string]bool{}
	for {
		var p struct {
			Service string `json:"Service"`
			State   string `json:"State"`
			Health  string `json:"Health"`
			Image   string `json:"Image"`
		}
		e = dec.Decode(&p)
		if e == io.EOF {
			break
		}
		if e != nil || seen[p.Service] || p.State != "running" || p.Health != "healthy" || rendered.Services[p.Service].Image != p.Image {
			return out, denied()
		}
		seen[p.Service] = true
	}
	if len(seen) != 4 || controller() != nil {
		return out, denied()
	}
	out.Digest = bytesDigest(b)
	return out, nil
}

// read maps only in-package disposable fixture roots; production always uses
// root-owned absolute paths through protected and cannot configure a root.
func (n *nativeRuntime) read(path string, max int64) ([]byte, os.FileInfo, error) {
	if n.root == "" || n.root == "/" {
		return protected(path, max)
	}
	p := filepath.Join(n.root, strings.TrimPrefix(path, "/"))
	st, e := os.Lstat(p)
	if e != nil || !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0077 != 0 {
		return nil, nil, denied()
	}
	if max == 0 {
		return nil, st, nil
	}
	b, e := os.ReadFile(p)
	if e != nil || int64(len(b)) > max {
		return nil, nil, denied()
	}
	return b, st, nil
}

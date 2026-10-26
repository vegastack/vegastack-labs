//go:build linux

package hostingplatform

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func platformFixtureConfig() map[string]any {
	services := map[string]any{}
	for _, name := range []string{"coolify", "postgres", "redis", "soketi"} {
		image := name + ":fixture@sha256:" + strings.Repeat("a", 64)
		s := map[string]any{"image": image, "volumes": []any{map[string]string{"type": "bind", "source": "/data/coolify/" + name}}, "environment": map[string]string{}}
		if name == "coolify" {
			s["image"] = "docker.io/coollabsio/coolify:4.3.10@sha256:" + strings.Repeat("a", 64)
			s["environment"] = map[string]string{"AUTOUPDATE": "false"}
			s["ports"] = []any{map[string]any{"target": 8080, "published": "8000", "host_ip": "127.0.0.1"}}
		}
		services[name] = s
	}
	return map[string]any{"services": services}
}
func TestHostingPlatformProcessPeer(t *testing.T) {
	root := os.Getenv("VSK_HOSTING_TEST_ROOT")
	if root == "" {
		return
	}
	args := os.Args
	sep := 0
	for i, a := range args {
		if a == "--" {
			sep = i + 1
			break
		}
	}
	if sep == 0 {
		os.Exit(2)
	}
	args = args[sep:]
	if args[0] == "/usr/bin/systemctl" {
		fmt.Print("active\n")
		os.Exit(0)
	}
	joined := strings.Join(args, " ")
	switch {
	case strings.Contains(joined, " config --format json"):
		b, _ := os.ReadFile(filepath.Join(root, "config.json"))
		os.Stdout.Write(b)
	case strings.Contains(joined, " up --detach --wait --wait-timeout 40 --no-build --pull never"):
		os.WriteFile(filepath.Join(root, "effect"), []byte("started"), 0600)
		if os.Getenv("VSK_HOSTING_TEST_FAIL") == "yes" {
			os.Exit(1)
		}
	case strings.Contains(joined, " ps --format json --all"):
		if _, e := os.Stat(filepath.Join(root, "effect")); os.IsNotExist(e) {
			os.Exit(0)
		}
		var c struct {
			Services map[string]composeService `json:"services"`
		}
		b, _ := os.ReadFile(filepath.Join(root, "config.json"))
		json.Unmarshal(b, &c)
		for name, s := range c.Services {
			json.NewEncoder(os.Stdout).Encode(map[string]any{"Service": name, "Image": s.Image, "State": "running", "Health": "healthy"})
		}
	default:
		os.Exit(2)
	}
	os.Exit(0)
}
func TestHostingPlatformNativeProcessInstallPreservesController(t *testing.T) {
	for _, mode := range []string{"success", "start-failure", "existing-data"} {
		fail := mode == "start-failure"
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			write := func(p string, b []byte) {
				p = filepath.Join(root, p)
				os.MkdirAll(filepath.Dir(p), 0700)
				if e := os.WriteFile(p, b, 0600); e != nil {
					t.Fatal(e)
				}
			}
			compose := []byte("protected-reviewed-compose")
			env := []byte("AUTOUPDATE=false\n")
			unit := []byte("existing-controller-unit")
			db := []byte("controller-private-records")
			write("data/coolify/compose.yaml", compose)
			write("data/coolify/environment", env)
			write("etc/systemd/system/vsk-labs.service", unit)
			write("var/lib/vsk-labs/control.db", db)
			b, _ := json.Marshal(platformFixtureConfig())
			write("config.json", b)
			if mode == "existing-data" {
				write("data/coolify/postgres/record", []byte("must-survive"))
			}
			run := func(ctx context.Context, bin string, args []string) ([]byte, error) {
				a := append([]string{"-test.run=^TestHostingPlatformProcessPeer$", "--", bin}, args...)
				cmd := exec.CommandContext(ctx, os.Args[0], a...)
				cmd.Env = append(os.Environ(), "VSK_HOSTING_TEST_ROOT="+root)
				if fail {
					cmd.Env = append(cmd.Env, "VSK_HOSTING_TEST_FAIL=yes")
				}
				return cmd.Output()
			}
			n := &nativeRuntime{root: root, run: run}
			out, e := n.Execute(context.Background(), InstallAction, Input{HostID: "control-a", HostIdentityDigest: "sha256:" + strings.Repeat("a", 64), ComponentDirectory: "/data/coolify", ComposeDigest: bytesDigest(compose), EnvironmentDigest: bytesDigest(env), PrivateAddress: "127.0.0.1", ManagementPort: 8000, ControllerDatabasePath: "/var/lib/vsk-labs/control.db", ControllerUnitDigest: bytesDigest(unit)})
			if mode == "existing-data" {
				if e == nil || out.Changed {
					t.Fatal("existing data install accepted", out, e)
				}
			} else if !out.Changed || (e != nil) != fail {
				t.Fatal(out, e)
			}
			got, _ := os.ReadFile(filepath.Join(root, "var/lib/vsk-labs/control.db"))
			if string(got) != string(db) {
				t.Fatal("controller data changed")
			}
			if _, e = os.Stat(filepath.Join(root, "effect")); mode == "existing-data" {
				if !os.IsNotExist(e) {
					t.Fatal("existing data triggered process write")
				}
			} else if e != nil {
				t.Fatal("native command never executed", e)
			}
		})
	}
}
func TestHostingPlatformRejectsExposureAndPrivilegeBeforeStart(t *testing.T) {
	in := Input{ComponentDirectory: "/data/coolify", PrivateAddress: "127.0.0.1", ManagementPort: 8000}
	for _, kind := range []string{"privileged", "host-ip", "mount", "update", "version"} {
		t.Run(kind, func(t *testing.T) {
			c := platformFixtureConfig()
			s := c["services"].(map[string]any)["coolify"].(map[string]any)
			switch kind {
			case "privileged":
				s["privileged"] = true
			case "host-ip":
				s["ports"] = []any{map[string]any{"target": 8080, "published": "8000", "host_ip": "0.0.0.0"}}
			case "mount":
				s["volumes"] = []any{map[string]string{"type": "bind", "source": "/var/lib/vsk-labs"}}
			case "update":
				s["environment"] = map[string]string{"AUTOUPDATE": "true"}
			case "version":
				s["image"] = "coollabsio/coolify:latest@sha256:" + strings.Repeat("a", 64)
			}
			raw, _ := json.Marshal(c)
			if validateCompose(raw, in) == nil {
				t.Fatal("unsafe config accepted")
			}
		})
	}
}

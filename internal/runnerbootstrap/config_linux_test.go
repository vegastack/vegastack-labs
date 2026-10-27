//go:build linux

package runnerbootstrap

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"golang.org/x/sys/unix"
)

const syntheticToken = "SYNTHETIC-REGISTRATION-TOKEN"

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "configure" {
		os.Exit(fixtureChild())
	}
	os.Exit(m.Run())
}
func fixtureChild() int {
	term, err := unix.IoctlGetTermios(0, unix.TCGETS)
	if err != nil || term.Lflag&(unix.ECHO|unix.ECHONL) != 0 {
		return 31
	}
	sid, err := unix.IoctlGetInt(0, unix.TIOCGSID)
	if err != nil || sid != os.Getpid() {
		return 32
	}
	if len(os.Environ()) != 0 {
		return 33
	}
	want := []string{"configure", "--url", "https://github.com/fixture-org", "--name", "fixture-runner", "--runnergroup", "fixture group", "--labels", "linux,isolated", "--work", "_work", "--ephemeral", "--disableupdate", "--no-default-labels"}
	if !reflect.DeepEqual(os.Args[1:], want) {
		return 34
	}
	raw, _ := os.ReadFile("fixture-mode")
	mode := string(raw)
	switch mode {
	case "wrong":
		fmt.Print("Enter unexpected password: ")
		time.Sleep(time.Minute)
		return 1
	case "missing":
		time.Sleep(time.Minute)
		return 1
	case "overflow":
		fmt.Print(strings.Repeat("x", 70000))
		return 1
	}
	fmt.Print("# Authentication\nWhat is your runner register token? ")
	token, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil || strings.TrimSpace(token) != syntheticToken {
		return 35
	}
	term, err = unix.IoctlGetTermios(0, unix.TCGETS)
	if err != nil || term.Lflag&(unix.ECHO|unix.ECHONL) != 0 {
		return 36
	}
	if mode == "repeat" {
		fmt.Print("What is your runner register token? ")
		time.Sleep(time.Minute)
		return 1
	}
	if mode == "echo" {
		fmt.Print(token)
		return 0
	}
	if mode == "exit" {
		return 7
	}
	if mode == "hang" {
		os.WriteFile("fixture-pid", []byte(strconv.Itoa(os.Getpid())), 0600)
		time.Sleep(time.Minute)
		return 1
	}
	cfg := map[string]any{"agentId": 123, "agentName": "fixture-runner", "poolId": 456, "poolName": "fixture group", "gitHubUrl": "https://github.com/fixture-org", "workFolder": "_work", "ephemeral": true, "disableUpdate": true}
	switch mode {
	case "wrong settings":
		cfg["agentName"] = "other"
	case "missing settings":
		return 0
	case "unsafe settings":
		os.Symlink("fixture-mode", ".runner")
		return 0
	}
	data, _ := json.Marshal(cfg)
	if os.WriteFile(".runner", data, 0600) != nil {
		return 37
	}
	fmt.Print(strings.Repeat("*", len(syntheticToken)) + "\nConnected to GitHub\nSettings Saved.\n")
	return 0
}
func setup(t *testing.T, mode string) (Config, *credentialref.Value) {
	t.Helper()
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	if err := os.Mkdir(filepath.Join(dir, "bin"), 0700); err != nil {
		t.Fatal(err)
	}
	exe, _ := os.Executable()
	src, err := os.Open(exe)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	dst, err := os.OpenFile(filepath.Join(dir, "bin", "Runner.Listener"), os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0700)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(dst, src)
	dst.Close()
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "fixture-mode"), []byte(mode), 0600)
	v, _ := credentialref.NewValue([]byte(syntheticToken))
	t.Cleanup(v.Close)
	return Config{Directory: dir, Organization: "fixture-org", Name: "fixture-runner", Group: "fixture group", Labels: []string{"linux", "isolated"}, ExpiresAt: time.Now().Add(3 * time.Second), Check: func() error { return nil }}, v
}
func TestConfigureNativePTY(t *testing.T) {
	cfg, v := setup(t, "")
	out, err := Configure(context.Background(), cfg, v)
	if err != nil || out.Stage != "configured" {
		t.Fatal(out, err)
	}
	if string(v.Bytes()) != syntheticToken {
		t.Fatal("consumer changed borrowed token")
	}
}
func TestConfigureDenials(t *testing.T) {
	for _, mode := range []string{"wrong", "missing", "overflow", "repeat", "echo", "exit", "hang", "wrong settings", "missing settings", "unsafe settings"} {
		t.Run(mode, func(t *testing.T) {
			cfg, v := setup(t, mode)
			cfg.ExpiresAt = time.Now().Add(300 * time.Millisecond)
			out, err := Configure(context.Background(), cfg, v)
			if err == nil || out.Stage == "configured" {
				t.Fatal(out, err)
			}
			if strings.Contains(err.Error(), syntheticToken) {
				t.Fatal("secret error")
			}
			if mode == "hang" {
				raw, _ := os.ReadFile(filepath.Join(cfg.Directory, "fixture-pid"))
				pid, _ := strconv.Atoi(string(raw))
				if pid <= 0 || unix.Kill(pid, 0) != unix.ESRCH {
					t.Fatal("child survived", pid)
				}
			}
		})
	}
}
func TestConfigureInputAndCancellation(t *testing.T) {
	for _, kind := range []string{"canceled", "expired", "future", "directory", "org", "name", "group", "labels", "check", "closed token", "existing"} {
		t.Run(kind, func(t *testing.T) {
			cfg, v := setup(t, "")
			ctx := context.Background()
			switch kind {
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "expired":
				cfg.ExpiresAt = time.Now().Add(-time.Second)
			case "future":
				cfg.ExpiresAt = time.Now().Add(2 * time.Hour)
			case "directory":
				cfg.Directory = "relative"
			case "org":
				cfg.Organization = "../other"
			case "name":
				cfg.Name = "--token"
			case "group":
				cfg.Group = "bad\n"
			case "labels":
				cfg.Labels = []string{"linux", "LINUX"}
			case "check":
				cfg.Check = func() error { return fmt.Errorf("%s", syntheticToken) }
			case "closed token":
				v.Close()
			case "existing":
				os.WriteFile(filepath.Join(cfg.Directory, ".runner"), []byte("{}"), 0600)
			}
			out, err := Configure(ctx, cfg, v)
			if err == nil || out.Stage == "configured" {
				t.Fatal(out, err)
			}
			if strings.Contains(err.Error(), syntheticToken) {
				t.Fatal("token leaked")
			}
		})
	}
}

// This opt-in test must run only in the operator-approved disposable guest with
// no external network interfaces. It supplies a synthetic token to the pinned
// official binary, then cancels; it cannot establish provider registration.
func TestConfigureOfficialPromptIsolated(t *testing.T) {
	directory := os.Getenv("VSK_RUNNERBOOTSTRAP_OFFICIAL_DIRECTORY")
	if directory == "" {
		t.Skip("requires an explicitly selected official installation in the isolated test guest")
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatal("official prompt proof requires a private network namespace with loopback only")
	}
	value, err := credentialref.NewValue([]byte(syntheticToken))
	if err != nil {
		t.Fatal("synthetic value rejected")
	}
	defer value.Close()
	cfg := Config{Directory: directory, Organization: "fixture-org", Name: "fixture-runner", Group: "fixture group", Labels: []string{"linux", "isolated"}, ExpiresAt: time.Now().Add(5 * time.Second), Check: func() error { return nil }}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	receipt, err := Configure(ctx, cfg, value)
	if err == nil || receipt.Stage != "registration_secret_delivered" {
		t.Fatalf("official binary did not consume protected prompt: receipt=%+v error=%v", receipt, err)
	}
	if string(value.Bytes()) != syntheticToken {
		t.Fatal("consumer modified borrowed token")
	}
}

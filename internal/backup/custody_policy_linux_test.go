//go:build linux

package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const custodyFixtureUID = 20163

func TestCustodyPolicyDeniesControllerRepositoryPath(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires disposable root-owned ext4 fixture")
	}
	base, err := os.MkdirTemp("/var/lib", "vsk-custody-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	makeOwned := func(name string) string {
		path := filepath.Join(base, name)
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(path, custodyFixtureUID, custodyFixtureUID); err != nil {
			t.Fatal(err)
		}
		return path
	}
	standard, critical := makeOwned("standard"), makeOwned("critical")
	standardQuarantine, criticalQuarantine := makeOwned("standard-quarantine"), makeOwned("critical-quarantine")
	makeControllerOwned := func(name string, mode os.FileMode) string {
		path := filepath.Join(base, name)
		if err := os.Mkdir(path, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(path, custodyFixtureUID+1, custodyFixtureUID+1); err != nil {
			t.Fatal(err)
		}
		return path
	}
	requestRoot := makeControllerOwned("requests", 0o700)
	exchangeRoot := makeControllerOwned("exchange", 0o711)
	probe := filepath.Join(standard, "pack-a")
	if err := os.WriteFile(probe, []byte("fixture ciphertext"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(probe, custodyFixtureUID, custodyFixtureUID); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(binary)
	policy := CustodyPolicy{SchemaVersion: "1.0.0", StandardRoot: standard, CriticalRoot: critical,
		StandardQuarantine: standardQuarantine, CriticalQuarantine: criticalQuarantine,
		OwnerUID: custodyFixtureUID, OwnerGID: custodyFixtureUID, ControllerUID: custodyFixtureUID + 1,
		ResticUID: custodyFixtureUID + 2, RequestRoot: requestRoot, ExchangeRoot: exchangeRoot,
		UnitTemplate: "vsk-labs-backup-custody@.service", ExecutablePath: executable, ResticBinaryPath: "/bin/true",
		ExecutableDigest: "sha256:" + hex.EncodeToString(sum[:]),
		MaximumLifetime:  10 * time.Minute}
	policyPath := filepath.Join(base, "custody-policy.json")
	encoded, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCustodyPolicy(policyPath)
	if err != nil || loaded != policy {
		t.Fatalf("load fixed policy: %v", err)
	}
	if err := VerifyCustodyPaths(loaded, "writer"); err != nil {
		t.Fatalf("verify exclusive paths: %v", err)
	}
	for _, identity := range []uint32{policy.ControllerUID, policy.ResticUID} {
		command := exec.Command(os.Args[0], "-test.run=^TestCustodyDeniedProbe$")
		command.Env = append(os.Environ(), "VSK_CUSTODY_DENIED_PROBE="+standard)
		command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: identity, Gid: identity}}
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("identity %d mutated protected path: %v %s", identity, err, output)
		}
	}
	if err := os.Chmod(standard, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := VerifyCustodyPaths(loaded, "writer"); err == nil {
		t.Fatal("group-writable repository accepted")
	}
	if err := os.Chmod(standard, 0o700); err != nil {
		t.Fatal(err)
	}
	wrongUID := loaded
	wrongUID.ControllerUID = wrongUID.OwnerUID
	if err := VerifyCustodyPaths(wrongUID, "writer"); err == nil {
		t.Fatal("controller sharing custody UID accepted")
	}
	alias := loaded
	alias.CriticalRoot = alias.StandardRoot
	if err := VerifyCustodyPaths(alias, "writer"); err == nil {
		t.Fatal("aliased repository roots accepted")
	}
	if err := os.Chmod(base, 0o775); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCustodyPolicy(policyPath); err == nil {
		t.Fatal("writable policy ancestor accepted")
	}
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "linked-root")
	if err := os.Symlink(standard, link); err != nil {
		t.Fatal(err)
	}
	alias = loaded
	alias.StandardRoot = link
	if err := VerifyCustodyPaths(alias, "writer"); err == nil {
		t.Fatal("symlink repository root accepted")
	}
	if err := os.Chown(critical, int(policy.ControllerUID), int(policy.ControllerUID)); err != nil {
		t.Fatal(err)
	}
	if err := VerifyCustodyPaths(loaded, "writer"); err == nil {
		t.Fatal("controller-owned repository accepted")
	}
	if err := os.Chown(critical, custodyFixtureUID, custodyFixtureUID); err != nil {
		t.Fatal(err)
	}
	wrongBinary := policy
	wrongBinary.ExecutableDigest = "sha256:" + hex.EncodeToString(make([]byte, sha256.Size))
	encoded, err = json.Marshal(wrongBinary)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCustodyPolicy(policyPath); err == nil {
		t.Fatal("wrong running executable digest accepted")
	}
}

func TestCustodyDeniedProbe(t *testing.T) {
	root := os.Getenv("VSK_CUSTODY_DENIED_PROBE")
	if root == "" {
		return
	}
	if err := os.Rename(filepath.Join(root, "pack-a"), filepath.Join(root, "pack-b")); !errors.Is(err, unix.EACCES) {
		t.Fatalf("rename: %v", err)
	}
	if err := os.Remove(filepath.Join(root, "pack-a")); !errors.Is(err, unix.EACCES) {
		t.Fatalf("unlink: %v", err)
	}
	if _, err := os.OpenFile(filepath.Join(root, "new-pack"), os.O_CREATE|os.O_WRONLY, 0o600); !errors.Is(err, unix.EACCES) {
		t.Fatalf("create: %v", err)
	}
	if directory, err := os.Open(root); !errors.Is(err, unix.EACCES) {
		if err == nil {
			_ = directory.Close()
		}
		t.Fatalf("directory open: %v", err)
	}
	if err := os.Chmod(filepath.Join(root, "pack-a"), 0o666); !errors.Is(err, unix.EACCES) {
		t.Fatalf("chmod: %v", err)
	}
}

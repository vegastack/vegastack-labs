//go:build linux

package qualification

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"os/exec"
	"syscall"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostreplacement"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

func TestNativeControllerIdentityNonrootChild(t *testing.T) {
	if os.Getenv("VSK_NATIVE_IDENTITY_CHILD") != "1" {
		t.Skip("child helper")
	}
	if os.Geteuid() != 65534 || unix.Fchdir(3) != nil {
		t.Fatal("service identity")
	}
	if _, err := os.ReadFile("dmi-root-only"); err == nil {
		t.Fatal("service unexpectedly read root-only DMI")
	}
	var scope generated.QualificationScope
	if json.Unmarshal([]byte(os.Getenv("VSK_NATIVE_IDENTITY_SCOPE")), &scope) != nil {
		t.Fatal("scope")
	}
	measured, err := measureControllerIdentityFiles(scope, "current-controller", scope.ExecutableDigest, "machine-id", "host-key.pub")
	if err != nil || measured.HostID != "controller-host" || measured.HostMachineID != scope.Guests[0].MachineID {
		t.Fatal("nonroot measured identity failed")
	}
	scope.Guests[0].MachineID = "22222222222222222222222222222222"
	if _, err = measureControllerIdentityFiles(scope, "current-controller", scope.ExecutableDigest, "machine-id", "host-key.pub"); err == nil {
		t.Fatal("machine substitution accepted")
	}
}
func TestNativeControllerIdentityUsesPreparedPinWithoutRootDMIRead(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires approved disposable root fork test")
	}
	root := t.TempDir()
	if os.Chmod(root, 0755) != nil {
		t.Fatal("mode")
	}
	machine := "11111111111111111111111111111111"
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	wire := ssh.MarshalAuthorizedKey(key)
	for path, data := range map[string][]byte{"machine-id": []byte(machine + "\n"), "host-key.pub": wire, "dmi-root-only": []byte("root-serial\n")} {
		mode := os.FileMode(0644)
		if path == "dmi-root-only" {
			mode = 0400
		}
		if os.WriteFile(root+"/"+path, data, mode) != nil {
			t.Fatal("fixture file")
		}
	}
	keyDigest, err := hostreplacement.SSHHostKeyDigest(string(wire))
	if err != nil {
		t.Fatal(err)
	}
	scope := scopeFixture()
	scope.Guests[0].MachineID = machine
	scope.Guests[0].SSHHostKeyDigest = keyDigest
	scope.ExecutableDigest = hostaction.Digest("test executable observation")
	raw, _ := json.Marshal(scope)
	directory, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	command := exec.Command("/proc/self/exe", "-test.run=^TestNativeControllerIdentityNonrootChild$")
	command.Dir = "/"
	command.Env = []string{"VSK_NATIVE_IDENTITY_CHILD=1", "VSK_NATIVE_IDENTITY_SCOPE=" + string(raw)}
	command.ExtraFiles = []*os.File{directory}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("actual nonroot child: %v %s", err, output)
	}
}

//go:build linux

package qualification

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"testing"
	"time"
)

func TestNativeAPIPrivilegeChild(t *testing.T) {
	path := os.Getenv("VSK_NATIVE_API_TEST_SOCKET")
	if path == "" {
		t.Skip("child helper")
	}
	if os.Getuid() != 65534 || os.Geteuid() != 65534 || os.Getgid() != 65534 || os.Getegid() != 65534 {
		t.Fatal("service identity not dropped")
	}
	groups, err := os.Getgroups()
	if err != nil || len(groups) != 0 {
		t.Fatal("supplementary groups retained")
	}
	c, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err = c.Write([]byte("typed-api-peer")); err != nil {
		t.Fatal(err)
	}
}

func TestNativeAPIChildUsesActualServiceOSPeer(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires approved disposable root fork test")
	}
	dir, err := os.MkdirTemp("/var/tmp", "vsk-native-api-peer-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if err = os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	path := dir + "/control.sock"
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err = os.Chown(path, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c := nativeAPICommand(ctx, generated.QualificationScope{ControlServiceUID: 65534, ControlServiceGID: 65534}, "-test.run=^TestNativeAPIPrivilegeChild$")
	c.Env = append(c.Env, "VSK_NATIVE_API_TEST_SOCKET="+path)
	done := make(chan error, 1)
	go func() { done <- c.Run() }()
	_ = l.SetDeadline(time.Now().Add(5 * time.Second))
	conn, err := l.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sc, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var cred *unix.Ucred
	var peerErr error
	if err = sc.Control(func(fd uintptr) { cred, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil || peerErr != nil || cred == nil || cred.Uid != 65534 || cred.Gid != 65534 {
		t.Fatal("API socket did not see service OS peer", cred, err, peerErr)
	}
	if err = <-done; err != nil {
		t.Fatal("service child failed", err)
	}
}

func TestNativeAPIPacketCannotBroadenRootStep(t *testing.T) {
	scope, err := validateScope(scopeFixture())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	step := generated.NativeStepRequest{Schema: generated.SchemaIDNativeStepRequest, SchemaVersion: "1.0.0", ScopeDigest: scope.digest, GuestID: "subject", ScenarioID: "baseline-access", Ordinal: 1, ControllerInstanceID: scope.value.ControllerInstanceID, RecoveryEpoch: 0, Nonce: hostaction.Digest("nonce"), Deadline: now.Add(time.Minute).Format(time.RFC3339), Operation: "execute", PlanID: "plan-one", PlanDigest: hostaction.Digest("plan")}
	in := nativeAPIPacket{Kind: "execute", Step: step}
	if validateAPIPacket(scope, in, now) != nil {
		t.Fatal("finite execute rejected")
	}
	for _, variant := range []string{"kind", "mixed", "scope", "missing-plan", "privileged-witness"} {
		t.Run(variant, func(t *testing.T) {
			bad := in
			switch variant {
			case "kind":
				bad.Kind = "shell"
			case "mixed":
				bad.Preparation = &generated.NativePreparationRequest{}
			case "scope":
				bad.Step.ScopeDigest = hostaction.Digest("outside")
			case "missing-plan":
				bad.Step.PlanID = ""
			case "privileged-witness":
				bad.Kind = "witness"
			}
			if validateAPIPacket(scope, bad, now) == nil {
				t.Fatal("broadened child request admitted")
			}
		})
	}
}

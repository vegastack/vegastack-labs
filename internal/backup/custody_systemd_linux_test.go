//go:build linux

package backup

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestEffectiveCustodyStartPolicyRequiresExactNarrowGrant(t *testing.T) {
	unit := "vsk-labs-backup-custody@0123456789abcdef0123456789abcdef.service"
	subject := "123,456,21164"
	policy := CustodyPolicy{ExecutablePath: "/usr/local/bin/vsk-labs"}
	exact := func(_ context.Context, path string, args []string) int {
		if path != "/usr/bin/sudo" {
			return -1
		}
		joined := strings.Join(args, " ")
		if joined == "-n -l -- "+policy.ExecutablePath+" "+CustodyPolicyCheckMode {
			return 0
		}
		return 1
	}
	aggregate := func(context.Context) ([]byte, error) {
		return []byte("Matching Defaults entries for vsk-controller on host:\n    env_reset\n\nUser vsk-controller may run the following commands on host:\n    (root) NOPASSWD: " + policy.ExecutablePath + " " + CustodyPolicyCheckMode + "\n"), nil
	}
	rootCheck := func(context.Context, CustodyPolicy, string, string) bool { return true }
	if !effectiveCustodyStartPolicy(context.Background(), policy, unit, subject, exact, aggregate, rootCheck) {
		t.Fatal("exact custody authority rejected")
	}
	if effectiveCustodyStartPolicy(context.Background(), policy, unit, subject, func(context.Context, string, []string) int { return 0 }, aggregate, rootCheck) {
		t.Fatal("broad custody authority accepted")
	}
	if effectiveCustodyStartPolicy(context.Background(), policy, "other.service", subject, exact, aggregate, rootCheck) {
		t.Fatal("foreign custody unit accepted")
	}
	if effectiveCustodyStartPolicy(context.Background(), policy, unit, subject, exact, aggregate, func(context.Context, CustodyPolicy, string, string) bool { return false }) {
		t.Fatal("failed root policy qualification accepted")
	}
}

func TestCustodyLaunchFrameDoesNotConsumeFollowingCommand(t *testing.T) {
	left, right, err := socketPair("systemd-launch-frame")
	if err != nil {
		t.Fatal(err)
	}
	defer left.Close()
	defer right.Close()
	nonce := "sha256:" + strings.Repeat("a", 64)
	first := custodyFrame{Type: "launch", NonceDigest: nonce, Payload: []byte(`{"nonce":"one"}`)}
	second := custodyFrame{Type: "ready", NonceDigest: nonce}
	if err := writeCustodyFrame(left, first); err != nil {
		t.Fatal(err)
	}
	if err := writeCustodyFrame(left, second); err != nil {
		t.Fatal(err)
	}
	gotFirst, err := readCustodyFrame(right)
	if err != nil || gotFirst.Type != first.Type || string(gotFirst.Payload) != string(first.Payload) {
		t.Fatalf("first frame=%#v err=%v", gotFirst, err)
	}
	gotSecond, err := readCustodyFrame(right)
	if err != nil || gotSecond.Type != second.Type || gotSecond.NonceDigest != nonce {
		t.Fatalf("second frame=%#v err=%v", gotSecond, err)
	}
}

func TestBrokeredResticRejectsCallerSelectedAuthority(t *testing.T) {
	policy := CustodyPolicy{
		StandardRoot: "/var/lib/vsk/standard", CriticalRoot: "/var/lib/vsk/critical",
		ExchangeRoot: "/var/lib/vsk/exchange", ResticBinaryPath: "/usr/local/bin/restic",
		ControllerUID: 21164, ResticUID: 21165,
	}
	session := CustodySession{RepositoryID: "repository-a", RepositoryClass: "standard"}
	base := ResticRequest{Mode: "config", BinaryPath: policy.ResticBinaryPath, RepositoryID: session.RepositoryID,
		RepositoryClass: session.RepositoryClass, RepositoryRoot: policy.StandardRoot, ExchangeRoot: policy.ExchangeRoot,
		ExecutionUID: policy.ResticUID, ExecutionGID: policy.ResticUID, ControllerUID: policy.ControllerUID}
	for name, mutate := range map[string]func(*ResticRequest){
		"repository URL": func(request *ResticRequest) { request.RepositoryURL = "file:///forged" },
		"binary":         func(request *ResticRequest) { request.BinaryPath = "/tmp/restic" },
		"root":           func(request *ResticRequest) { request.RepositoryRoot = "/tmp/repository" },
		"exchange":       func(request *ResticRequest) { request.ExchangeRoot = "/tmp/exchange" },
		"restic uid":     func(request *ResticRequest) { request.ExecutionUID++ },
		"controller uid": func(request *ResticRequest) { request.ControllerUID++ },
		"mode":           func(request *ResticRequest) { request.Mode = "forget" },
	} {
		t.Run(name, func(t *testing.T) {
			forged := base
			mutate(&forged)
			if err := prepareBrokeredRestic(policy, session, "http+unix:///run/custody.sock:/repository-a/", &forged); err == nil {
				t.Fatal("forged restic authority accepted")
			}
		})
	}
}

func TestCustodySupervisorRejectsDirectInvocation(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("non-root test process exercises the direct invocation denial")
	}
	if err := RunCustodySupervisor(strings.Repeat("a", 32)); err == nil {
		t.Fatal("non-systemd supervisor invocation accepted")
	}
}

func TestCustodySessionRejectsExpiredSystemdBoundary(t *testing.T) {
	now := time.Now().UTC()
	session := CustodySession{ProtocolVersion: CustodyProtocolVersion, Role: "writer", MaximumExpiresAt: now}
	if session.valid(now, time.Minute) {
		t.Fatal("expired systemd custody session accepted")
	}
}

//go:build linux

package backup

import (
	"os"
	"strings"
	"testing"
	"time"
)

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

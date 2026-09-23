//go:build linux

package backup

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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

func TestSystemdCustodyPoisonRejectsResticIndependentOfChildExit(t *testing.T) {
	client := &systemdCustodyClient{}
	client.poisoned.Store(true)
	if _, err := client.RunRestic(context.Background(), ResticRequest{Mode: "forget"}, nil); err == nil || !strings.Contains(err.Error(), "journal uncertain") {
		t.Fatalf("poisoned custody admitted restic result: %v", err)
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
			if transfer, err := prepareBrokeredRestic(policy, session, "http+unix:///run/custody.sock:/repository-a/", &forged); err == nil || transfer != nil {
				t.Fatal("forged restic authority accepted")
			}
		})
	}
}

func TestBrokeredRetentionModesRequireRetentionSession(t *testing.T) {
	policy := CustodyPolicy{
		StandardRoot: "/var/lib/vsk/standard", CriticalRoot: "/var/lib/vsk/critical",
		ExchangeRoot: "/var/lib/vsk/exchange", ResticBinaryPath: "/usr/local/bin/restic",
		ControllerUID: 21164, ResticUID: 21165,
	}
	request := ResticRequest{Mode: "forget", BinaryPath: policy.ResticBinaryPath, RepositoryID: "repository-a",
		RepositoryClass: "standard", RepositoryRoot: policy.StandardRoot, ExchangeRoot: policy.ExchangeRoot,
		ExecutionUID: policy.ResticUID, ExecutionGID: policy.ResticUID, ControllerUID: policy.ControllerUID,
		SnapshotIDs: []string{strings.Repeat("a", 64)}}
	writer := CustodySession{Role: "writer", RepositoryID: request.RepositoryID, RepositoryClass: request.RepositoryClass}
	if transfer, err := prepareBrokeredRestic(policy, writer, "http+unix:///run/custody.sock:/repository-a/", &request); err == nil || transfer != nil {
		t.Fatal("writer custody admitted retention command")
	}
	if request.RepositoryURL != "" {
		t.Fatal("rejected writer request mutated repository authority")
	}
	retention := writer
	retention.Role = "retention"
	for _, mode := range []string{"forget-dry-run", "forget", "prune"} {
		candidate := request
		candidate.Mode = mode
		if mode == "prune" {
			candidate.SnapshotIDs = nil
			candidate.MaxRepackBytes = 64 << 20
		}
		if transfer, err := prepareBrokeredRestic(policy, retention, "http+unix:///run/custody.sock:/repository-a/", &candidate); err != nil || transfer != nil {
			t.Fatalf("retention mode %s rejected: transfer=%v err=%v", mode, transfer, err)
		}
	}
}

func TestRejectedBrokeredExchangeNeverTouchesRootOrEtc(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("ownership sentinel regression requires disposable root")
	}
	rootBefore, err := os.Stat("/")
	if err != nil {
		t.Fatal(err)
	}
	etcBefore, err := os.Stat("/etc")
	if err != nil {
		t.Fatal(err)
	}
	policy := CustodyPolicy{StandardRoot: "/var/lib/vsk/standard", ExchangeRoot: "/var/lib/vsk/exchange", ResticBinaryPath: "/opt/restic", ControllerUID: 21164, ResticUID: 21165}
	session := CustodySession{RepositoryID: "repository-a", RepositoryClass: "standard"}
	base := ResticRequest{BinaryPath: policy.ResticBinaryPath, RepositoryID: session.RepositoryID, RepositoryClass: session.RepositoryClass,
		RepositoryRoot: policy.StandardRoot, ExchangeRoot: policy.ExchangeRoot, ExecutionUID: policy.ResticUID, ExecutionGID: policy.ResticUID, ControllerUID: policy.ControllerUID}
	for name, mutate := range map[string]func(*ResticRequest){
		"root restore": func(request *ResticRequest) { request.Mode, request.RestoreTarget = "restore", "/" },
		"etc backup":   func(request *ResticRequest) { request.Mode, request.SnapshotPath = "backup", "/etc/database.sqlite" },
	} {
		t.Run(name, func(t *testing.T) {
			request := base
			mutate(&request)
			run := false
			_, err := runBrokeredRestic(policy, session, "http+unix:///run/custody.sock:/repository-a/", &request, func() (ResticResult, error) {
				run = true
				return ResticResult{}, nil
			})
			if err == nil || run {
				t.Fatalf("forged exchange reached runner: run=%v err=%v", run, err)
			}
		})
	}
	rootAfter, _ := os.Stat("/")
	etcAfter, _ := os.Stat("/etc")
	if ownerUID(rootAfter) != ownerUID(rootBefore) || ownerUID(etcAfter) != ownerUID(etcBefore) {
		t.Fatal("forged exchange changed root or /etc ownership")
	}
}

func TestExchangeTransferRetainsValidatedDescriptorsAcrossSwap(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("descriptor ownership regression requires disposable root")
	}
	base, err := os.MkdirTemp("/var/lib", "vsk-custody-swap-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(base)
	exchange, sentinel := filepath.Join(base, "exchange"), filepath.Join(base, "sentinel")
	staging, moved := filepath.Join(exchange, ".vsk-backup-staging-swap"), filepath.Join(exchange, "moved")
	for _, path := range []string{exchange, sentinel, staging} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(exchange, 0o711); err != nil || os.Chown(exchange, 21164, 21164) != nil || os.Chown(staging, 21164, 21164) != nil {
		t.Fatal("fixture ownership failed")
	}
	snapshot := filepath.Join(staging, "database.sqlite")
	if err := os.WriteFile(snapshot, []byte("snapshot"), 0o600); err != nil || os.Chown(snapshot, 21164, 21164) != nil {
		t.Fatal("snapshot fixture failed")
	}
	policy := CustodyPolicy{ExchangeRoot: exchange, ControllerUID: 21164, ResticUID: 21165}
	transfer, err := prepareBackupExchangeWithHook(policy, snapshot, func() error {
		if err := os.Rename(staging, moved); err != nil {
			return err
		}
		return os.Symlink(sentinel, staging)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer transfer.Close()
	if err := transfer.ReturnOwnership(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{moved, filepath.Join(moved, "database.sqlite")} {
		info, err := os.Stat(path)
		if err != nil || ownerUID(info) != 21164 {
			t.Fatalf("retained object owner path=%s uid=%d err=%v", path, ownerUIDOrInvalid(info), err)
		}
	}
	sentinelInfo, err := os.Stat(sentinel)
	if err != nil {
		t.Fatal(err)
	}
	stat := sentinelInfo.Sys().(*syscall.Stat_t)
	if stat.Uid != 0 {
		t.Fatalf("swap sentinel owner=%d want=0", stat.Uid)
	}
}

func TestRestoreTransferRetainsValidatedDirectoryAcrossSwap(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("descriptor ownership regression requires disposable root")
	}
	base, err := os.MkdirTemp("/var/lib", "vsk-custody-restore-swap-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(base)
	exchange, sentinel := filepath.Join(base, "exchange"), filepath.Join(base, "sentinel")
	target, moved := filepath.Join(exchange, ".vsk-backup-verify-swap"), filepath.Join(exchange, "moved")
	for _, path := range []string{exchange, sentinel, target} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(exchange, 0o711); err != nil || os.Chown(exchange, 21164, 21164) != nil || os.Chown(target, 21164, 21164) != nil {
		t.Fatal("fixture ownership failed")
	}
	policy := CustodyPolicy{ExchangeRoot: exchange, ControllerUID: 21164, ResticUID: 21165}
	transfer, err := prepareRestoreExchangeWithHook(policy, target, func() error {
		if err := os.Rename(target, moved); err != nil {
			return err
		}
		return os.Symlink(sentinel, target)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer transfer.Close()
	if err := transfer.ReturnOwnership(); err != nil {
		t.Fatal(err)
	}
	movedInfo, err := os.Stat(moved)
	if err != nil || ownerUID(movedInfo) != 21164 {
		t.Fatalf("retained restore owner=%d err=%v", ownerUIDOrInvalid(movedInfo), err)
	}
	sentinelInfo, err := os.Stat(sentinel)
	if err != nil {
		t.Fatal(err)
	}
	if sentinelInfo.Sys().(*syscall.Stat_t).Uid != 0 {
		t.Fatalf("restore swap sentinel owner=%d want=0", ownerUID(sentinelInfo))
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

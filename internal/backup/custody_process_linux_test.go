//go:build linux

package backup

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type custodyTestJournal struct {
	mu               sync.Mutex
	starts, finishes []string
}

func (journal *custodyTestJournal) BeginCustody(_ context.Context, session CustodySession) error {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	journal.starts = append(journal.starts, session.LeaseID)
	return nil
}
func (journal *custodyTestJournal) FinishCustody(_ context.Context, session CustodySession, outcome string) error {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	journal.finishes = append(journal.finishes, session.LeaseID+":"+outcome)
	return nil
}

func TestCustodyChildProcess(t *testing.T) {
	if os.Getenv("VSK_BACKUP_CUSTODY") != "1" {
		return
	}
	if err := RunCustodyChild(os.Getenv("VSK_BACKUP_CUSTODY_POLICY")); err != nil {
		t.Fatal(err)
	}
}

func TestCustodyPeerProbe(t *testing.T) {
	socket := os.Getenv("VSK_CUSTODY_PEER_PROBE")
	if socket == "" {
		return
	}
	connection, err := net.Dial("unix", socket)
	if err != nil {
		if os.Getenv("VSK_CUSTODY_PEER_STATUS") == "closed" {
			return
		}
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.WriteString(connection, "GET /repository-a/config HTTP/1.1\r\nHost: custody\r\nConnection: close\r\n\r\n")
	response, err := http.ReadResponse(bufio.NewReader(connection), nil)
	want := os.Getenv("VSK_CUSTODY_PEER_STATUS")
	if want == "closed" {
		if err == nil {
			_ = response.Body.Close()
			t.Fatalf("foreign peer received status %d", response.StatusCode)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.Status != want {
		t.Fatalf("status=%q want=%q", response.Status, want)
	}
}

func TestCustodyProcessBindsLeaseInventoryAndOneProcess(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires disposable root-owned ext4 fixture")
	}
	policyPath, policy := custodyProcessPolicy(t)
	now := time.Now().UTC().Truncate(time.Second)
	lease := WriterLease{PolicyID: "policy-a", PointID: "point-a", PlanID: "plan-a", PlanDigest: "sha256:" + strings.Repeat("a", 64), RunID: "run-a", StepID: "step-a", LeaseID: "lease-a", RepositoryID: "repository-a", RepositoryClass: "standard", TargetID: "target-a", SourceRevision: 7, RecoveryEpoch: 2, MaximumExpiresAt: now.Add(5 * time.Minute)}
	session := CustodySession{ProtocolVersion: CustodyProtocolVersion, Role: "writer", PlanID: lease.PlanID, PlanDigest: lease.PlanDigest, RunID: lease.RunID, StepID: lease.StepID, LeaseID: lease.LeaseID, RepositoryID: lease.RepositoryID, RepositoryClass: lease.RepositoryClass, PointID: lease.PointID, SourceID: "source-a", SourceRevision: lease.SourceRevision, RecoveryEpoch: lease.RecoveryEpoch, MaximumExpiresAt: lease.MaximumExpiresAt, MaximumObjects: 100, MaximumBytes: 1 << 20, WriterLease: &lease}
	journal := &custodyTestJournal{}
	leaseVerifier := &allowingLeaseVerifier{}
	launcher := CustodyLauncher{PolicyPath: policyPath, Writer: leaseVerifier, Journal: journal, Clock: func() time.Time { return now }, command: []string{os.Args[0], "-test.run=^TestCustodyChildProcess$"}}
	client, err := launcher.Start(context.Background(), session)
	if err != nil {
		t.Fatal(err)
	}
	objects, err := client.Inventory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != 1 || objects[0].Type != "config" || objects[0].Name != "config" {
		t.Fatalf("inventory=%+v", objects)
	}
	if free, err := client.Capacity(context.Background()); err != nil || free == 0 {
		t.Fatalf("capacity=%d err=%v", free, err)
	}
	probe := func(uid uint32, status string) {
		t.Helper()
		command := exec.Command(os.Args[0], "-test.run=^TestCustodyPeerProbe$")
		command.Env = append(os.Environ(), "VSK_CUSTODY_PEER_PROBE="+client.(*processCustodyClient).socket, "VSK_CUSTODY_PEER_STATUS="+status)
		command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid}}
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("peer uid=%d status=%s: %v %s", uid, status, err, output)
		}
	}
	probe(policy.ControllerUID, "closed")
	probe(policy.ResticUID, "200 OK")
	leaseVerifier.err = io.EOF
	probe(policy.ResticUID, "403 Forbidden")
	leaseVerifier.err = nil
	if _, err := launcher.Start(context.Background(), session); err == nil {
		t.Fatal("second custodian started")
	}
	if err := client.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if len(journal.starts) != 2 || len(journal.finishes) != 2 || journal.finishes[1] != "lease-a:succeeded" {
		t.Fatalf("journal starts=%v finishes=%v", journal.starts, journal.finishes)
	}
}

func TestCustodySessionRejectsForgedBindings(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	lease := WriterLease{PointID: "point-a", PlanID: "plan-a", PlanDigest: "sha256:" + strings.Repeat("a", 64), RunID: "run-a", StepID: "step-a", LeaseID: "lease-a", RepositoryID: "repository-a", RepositoryClass: "standard", SourceRevision: 7, RecoveryEpoch: 2, MaximumExpiresAt: now.Add(time.Minute)}
	base := CustodySession{ProtocolVersion: CustodyProtocolVersion, Role: "writer", PlanID: lease.PlanID, PlanDigest: lease.PlanDigest, RunID: lease.RunID, StepID: lease.StepID, LeaseID: lease.LeaseID, RepositoryID: lease.RepositoryID, RepositoryClass: lease.RepositoryClass, PointID: lease.PointID, SourceID: "source-a", SourceRevision: lease.SourceRevision, RecoveryEpoch: lease.RecoveryEpoch, MaximumExpiresAt: lease.MaximumExpiresAt, MaximumObjects: 1, MaximumBytes: 1, NonceDigest: custodyNonceDigest([]byte("nonce")), WriterLease: &lease}
	for name, mutate := range map[string]func(*CustodySession){
		"plan":  func(session *CustodySession) { session.PlanID = "forged" },
		"epoch": func(session *CustodySession) { session.RecoveryEpoch++ },
		"lease": func(session *CustodySession) { session.LeaseID = "forged" },
		"nonce": func(session *CustodySession) { session.NonceDigest = "sha256:" + strings.Repeat("0", 63) },
	} {
		t.Run(name, func(t *testing.T) {
			forged := base
			mutate(&forged)
			if forged.valid(now, 10*time.Minute) {
				t.Fatal("forged custody session accepted")
			}
		})
	}
	expired := base
	expired.MaximumExpiresAt = now
	if expired.valid(now, 10*time.Minute) {
		t.Fatal("expired custody session accepted")
	}
}

func TestCustodyResponseLossRecordsUncertain(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires disposable root-owned ext4 fixture")
	}
	policyPath, _ := custodyProcessPolicy(t)
	now := time.Now().UTC().Truncate(time.Second)
	lease := WriterLease{PolicyID: "policy-loss", PointID: "point-loss", PlanID: "plan-loss", PlanDigest: "sha256:" + strings.Repeat("b", 64), RunID: "run-loss", StepID: "step-loss", LeaseID: "lease-loss", RepositoryID: "repository-loss", RepositoryClass: "standard", TargetID: "target-loss", SourceRevision: 8, RecoveryEpoch: 2, MaximumExpiresAt: now.Add(5 * time.Minute)}
	session := CustodySession{ProtocolVersion: CustodyProtocolVersion, Role: "writer", PlanID: lease.PlanID, PlanDigest: lease.PlanDigest, RunID: lease.RunID, StepID: lease.StepID, LeaseID: lease.LeaseID, RepositoryID: lease.RepositoryID, RepositoryClass: lease.RepositoryClass, PointID: lease.PointID, SourceID: "source-a", SourceRevision: lease.SourceRevision, RecoveryEpoch: lease.RecoveryEpoch, MaximumExpiresAt: lease.MaximumExpiresAt, MaximumObjects: 100, MaximumBytes: 1 << 20, WriterLease: &lease}
	journal := &custodyTestJournal{}
	launcher := CustodyLauncher{PolicyPath: policyPath, Writer: allowingLeaseVerifier{}, Journal: journal, Clock: func() time.Time { return now }, command: []string{os.Args[0], "-test.run=^TestCustodyChildProcess$"}}
	client, err := launcher.Start(context.Background(), session)
	if err != nil {
		t.Fatal(err)
	}
	process := client.(*processCustodyClient)
	if err := process.command.Close(); err != nil {
		t.Fatal(err)
	}
	closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Close(closeCtx); err == nil {
		t.Fatal("lost response reported success")
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if len(journal.finishes) != 1 || journal.finishes[0] != "lease-loss:uncertain" {
		t.Fatalf("journal finishes=%v", journal.finishes)
	}
}

func custodyProcessPolicy(t *testing.T) (string, CustodyPolicy) {
	t.Helper()
	base, err := os.MkdirTemp("/var/lib", "vsk-custody-process-")
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
	sq, cq := makeOwned("standard-q"), makeOwned("critical-q")
	if err := os.WriteFile(filepath.Join(standard, "config"), []byte("encrypted-config"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(filepath.Join(standard, "config"), custodyFixtureUID, custodyFixtureUID); err != nil {
		t.Fatal(err)
	}
	executable, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(executable)
	policy := CustodyPolicy{SchemaVersion: "1.0.0", StandardRoot: standard, CriticalRoot: critical, StandardQuarantine: sq, CriticalQuarantine: cq, OwnerUID: custodyFixtureUID, OwnerGID: custodyFixtureUID, ControllerUID: custodyFixtureUID + 1, ResticUID: custodyFixtureUID + 2, ExecutableDigest: "sha256:" + hex.EncodeToString(sum[:]), MaximumLifetime: 10 * time.Minute}
	body, _ := json.Marshal(policy)
	path := filepath.Join(base, "policy.json")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	return path, policy
}

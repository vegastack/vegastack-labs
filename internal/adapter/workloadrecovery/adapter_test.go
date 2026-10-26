package workloadrecovery

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter/serviceruntime"
	"github.com/vegastack/vegastack-labs/internal/backup"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"github.com/vegastack/vegastack-labs/internal/servicerecovery"
	"golang.org/x/crypto/ssh"
)

func testDigest(c string) string { return "sha256:" + strings.Repeat(c, 64) }
func tarFixture(t *testing.T, body string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	if e := w.WriteHeader(&tar.Header{Name: ".", Typeflag: tar.TypeDir, Mode: 0700}); e != nil {
		t.Fatal(e)
	}
	if body != "" {
		if e := w.WriteHeader(&tar.Header{Name: "data", Typeflag: tar.TypeReg, Mode: 0600, Size: int64(len(body))}); e != nil {
			t.Fatal(e)
		}
		_, _ = w.Write([]byte(body))
	}
	if e := w.Close(); e != nil {
		t.Fatal(e)
	}
	return b.Bytes()
}

type sshFixture struct {
	mu                                 sync.Mutex
	id, machine, project, image        string
	running                            bool
	archive                            []byte
	unexpected, failCapture, failStart bool
	stops, starts, copies              int
}

func sshPeer(t *testing.T, f *sshFixture) (serviceruntime.Target, *credentialref.Value) {
	t.Helper()
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	signer, e := ssh.NewSignerFromKey(key)
	if e != nil {
		t.Fatal(e)
	}
	der, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	value, e := credentialref.NewValue(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(value.Close)
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) { return nil, nil }}
	cfg.AddHostKey(signer)
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, e := listener.Accept()
			if e != nil {
				return
			}
			go func() {
				defer conn.Close()
				secure, chans, requests, e := ssh.NewServerConn(conn, cfg)
				if e != nil {
					return
				}
				defer secure.Close()
				go ssh.DiscardRequests(requests)
				for ch := range chans {
					if ch.ChannelType() != "session" {
						_ = ch.Reject(ssh.UnknownChannelType, "unknown")
						continue
					}
					channel, reqs, e := ch.Accept()
					if e != nil {
						return
					}
					go func() {
						defer channel.Close()
						for r := range reqs {
							if r.Type != "exec" {
								_ = r.Reply(false, nil)
								continue
							}
							var command struct{ Command string }
							_ = ssh.Unmarshal(r.Payload, &command)
							_ = r.Reply(true, nil)
							status := uint32(0)
							if !fixtureCommand(f, command.Command, channel) {
								status = 1
							}
							_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
							return
						}
					}()
				}
			}()
		}
	}()
	addr := listener.Addr().(*net.TCPAddr)
	return serviceruntime.Target{HostID: "host-" + f.project, HostIdentityDigest: testDigest("a"), Address: "127.0.0.1", Port: uint16(addr.Port), User: "fixture", HostKey: string(ssh.MarshalAuthorizedKey(signer.PublicKey())), ExpectedMachineIDDigest: hostdiscovery.Digest(f.machine)}, value
}
func fixtureCommand(f *sshFixture, cmd string, ch ssh.Channel) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case cmd == "/usr/bin/cat /etc/machine-id":
		_, _ = io.WriteString(ch, f.machine+"\n")
	case strings.Contains(cmd, "container ls "):
		_, _ = io.WriteString(ch, f.id+"\n")
		if f.unexpected {
			_, _ = io.WriteString(ch, strings.Repeat("f", 64)+"\n")
		}
	case strings.Contains(cmd, "container inspect "):
		v := inspected{ID: f.id, Image: testDigest("c"), Running: f.running, Health: "healthy", Project: f.project, Mounts: []mount{{Type: "volume", Name: "volume-" + f.project, Source: "/private/" + f.project, Destination: "/data", RW: true}}, Networks: map[string]struct{ NetworkID string }{"isolated": {NetworkID: "network-isolated"}}, Restart: "no"}
		raw, _ := json.Marshal(v)
		_, _ = ch.Write(raw)
	case strings.Contains(cmd, "image inspect "):
		_, _ = fmt.Fprintf(ch, "[%q]", "registry.invalid/project/image@"+f.image)
	case strings.Contains(cmd, "network inspect "):
		_, _ = io.WriteString(ch, "true\n")
	case strings.Contains(cmd, "container stop "):
		f.stops++
		f.running = false
		_, _ = io.WriteString(ch, f.id+"\n")
	case strings.Contains(cmd, "container start "):
		f.starts++
		if f.failStart {
			return false
		}
		f.running = true
		_, _ = io.WriteString(ch, f.id+"\n")
	case strings.Contains(cmd, "container cp -a - "):
		f.copies++
		b, e := io.ReadAll(io.LimitReader(ch, 1<<20))
		if e != nil {
			return false
		}
		f.archive = b
	case strings.Contains(cmd, "container cp -a "):
		if f.failCapture {
			return false
		}
		_, _ = ch.Write(f.archive)
	default:
		return false
	}
	return true
}

type failingRunner struct{}

func (failingRunner) Run(context.Context, backup.ResticRequest, *credentialref.Value) (backup.ResticResult, error) {
	return backup.ResticResult{}, unavailable()
}
func (failingRunner) Observation() backup.ResticObservation { return backup.ResticObservation{} }
func recoveryFixture(t *testing.T) (Config, generated.ServiceRecoveryRequest, backup.WriterLease, *sshFixture, *sshFixture) {
	t.Helper()
	source := &sshFixture{id: strings.Repeat("a", 64), machine: strings.Repeat("1", 32), project: "source", image: testDigest("b"), running: true, archive: tarFixture(t, "database-transaction-17\nblob-17\n")}
	target := &sshFixture{id: strings.Repeat("b", 64), machine: strings.Repeat("2", 32), project: "target", image: testDigest("b"), archive: tarFixture(t, "")}
	s, sk := sshPeer(t, source)
	d, dk := sshPeer(t, target)
	root := t.TempDir()
	repo := filepath.Join(root, "repository")
	exchange := filepath.Join(root, "exchange")
	_ = os.Mkdir(repo, 0700)
	_ = os.Mkdir(exchange, 0700)
	key, _ := credentialref.NewValue([]byte("isolated-workload-restic-fixture"))
	t.Cleanup(key.Close)
	binding := generated.ServiceRecoveryBinding{Schema: generated.SchemaIDServiceRecoveryBinding, SchemaVersion: "1.0.0", PolicyID: "policy-a", ServiceID: "service-a", ConfigurationDigest: testDigest("d"), DataClass: "workload", ConsistencyProcedureID: servicerecovery.ConsistencyProcedureID, SourceHostID: s.HostID, TargetHostID: d.HostID}
	profile := generated.ServiceRecoveryProfile{Schema: generated.SchemaIDServiceRecoveryProfile, SchemaVersion: "1.0.0", Binding: binding, SourceProject: "source", TargetProject: "target", Components: []generated.ServiceRecoveryComponent{{Schema: generated.SchemaIDServiceRecoveryComponent, SchemaVersion: "1.0.0", SourceContainerID: source.id, TargetContainerID: target.id, ImageDigest: source.image, Mounts: []generated.ServiceRecoveryMount{{Schema: generated.SchemaIDServiceRecoveryMount, SchemaVersion: "1.0.0", Destination: "/data", Type: "volume", Source: "volume-source", TargetSource: "volume-target"}}}}, TargetServiceID: "service-target", SourceReferenceID: "source-key", TargetReferenceID: "target-key", RepositoryKeyReferenceID: "repository-key", RepositoryID: "repo-workload", RepositoryRoot: repo, ExchangeRoot: exchange, ResticBinaryPath: "/fixture/restic", Architecture: runtime.GOARCH, MaximumBytes: 1 << 20, RecoveryObjectiveSeconds: 120}
	q := generated.ServiceRecoveryRequest{Schema: generated.SchemaIDServiceRecoveryRequest, SchemaVersion: "1.0.0", Definition: generated.ServiceDefinition{Schema: generated.SchemaIDServiceDefinition, SchemaVersion: "1.0.0", ServiceID: "service-a", EnvironmentID: "env-a", OwnerID: "owner-a", HostID: s.HostID, HostIdentityDigest: s.HostIdentityDigest, BindingID: "binding-a", BindingDigest: testDigest("e")}, Binding: binding, Action: "backup", IdempotencyKey: "request-a", ReasonDigest: testDigest("f")}
	lease := backup.WriterLease{PolicyID: binding.PolicyID, RepositoryID: profile.RepositoryID, RepositoryClass: "critical", LeaseID: "lease-a", PointID: "point-a", PlanID: "plan-a", PlanDigest: testDigest("a"), RunID: "run-a", StepID: "step-a", TargetID: q.Definition.ServiceID, MaximumExpiresAt: time.Now().Add(5 * time.Minute)}
	return Config{Profile: profile, Source: s, Target: d, SourceCredential: sk, TargetCredential: dk, RepositoryKey: key, Runner: failingRunner{}, Check: func(context.Context) error { return nil }}, q, lease, source, target
}
func TestWorkloadRecoveryPreservesSourceAcrossFailure(t *testing.T) {
	c, q, lease, source, _ := recoveryFixture(t)
	out, e := Execute(context.Background(), q, generated.ServiceRecoveryRecord{}, lease, c)
	if e == nil || out.Status != "partial" || !out.SourceResumed {
		t.Fatalf("failure must remain partial and restore original running set: %+v %v", out, e)
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if !source.running || source.stops != 1 || source.starts != 1 {
		t.Fatalf("source state running=%v stops=%d starts=%d", source.running, source.stops, source.starts)
	}
}
func TestWorkloadRecoveryRejectsIncompleteInventoryBeforeStop(t *testing.T) {
	c, q, lease, source, _ := recoveryFixture(t)
	source.unexpected = true
	_, e := Execute(context.Background(), q, generated.ServiceRecoveryRecord{}, lease, c)
	if e == nil {
		t.Fatal("unexpected stack component allowed")
	}
	if source.stops != 0 || source.starts != 0 {
		t.Fatal("incomplete inventory mutated stack")
	}
}
func TestServiceRecoveryRejectsUnsafeWriterCutover(t *testing.T) {
	c, q, lease, source, target := recoveryFixture(t)
	q.Action = "migration-cutover"
	q.BackupPointID = "point-a"
	previous := generated.ServiceRecoveryRecord{Request: q, Status: "succeeded", BackupPointID: "point-a", IsolatedRestoreVerified: true, SourceFenced: true, TargetWritersEnabled: true}
	out, e := Execute(context.Background(), q, previous, lease, c)
	if e == nil || out.NextAction != "roll-forward-required" {
		t.Fatalf("writer boundary did not force roll forward: %+v %v", out, e)
	}
	if source.stops+source.starts+target.stops+target.starts != 0 {
		t.Fatal("unsafe rollback touched stack")
	}
}
func TestWorkloadArchiveRejectsTraversalAndUnsafeLinks(t *testing.T) {
	for _, header := range []*tar.Header{{Name: "../database", Typeflag: tar.TypeReg, Mode: 0600}, {Name: "data", Linkname: "../../private", Typeflag: tar.TypeSymlink, Mode: 0777}} {
		t.Run(header.Name, func(t *testing.T) {
			var b bytes.Buffer
			w := tar.NewWriter(&b)
			_ = w.WriteHeader(header)
			_ = w.Close()
			p := filepath.Join(t.TempDir(), "hostile.tar")
			_ = os.WriteFile(p, b.Bytes(), 0600)
			if _, _, e := archiveProof(p, 1<<20, false); e == nil {
				t.Fatal("unsafe archive accepted")
			}
		})
	}
}

func TestWorkloadRecoveryCancellationRunsSourceCleanup(t *testing.T) {
	c, q, lease, source, _ := recoveryFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.Check = func(context.Context) error {
		source.mu.Lock()
		stopped := source.stops != 0
		source.mu.Unlock()
		if stopped {
			cancel()
			return context.Canceled
		}
		return nil
	}
	out, e := Execute(ctx, q, generated.ServiceRecoveryRecord{}, lease, c)
	if e == nil || !out.SourceResumed || !source.running || source.starts != 1 {
		t.Fatalf("cancellation failed exact cleanup: %+v %v starts=%d running=%v", out, e, source.starts, source.running)
	}
}
func TestWorkloadRecoveryFailedRestartRemainsPartial(t *testing.T) {
	c, q, lease, source, _ := recoveryFixture(t)
	source.failStart = true
	out, e := Execute(context.Background(), q, generated.ServiceRecoveryRecord{}, lease, c)
	if e == nil || out.Status != "partial" || out.SourceResumed || source.running {
		t.Fatalf("failed restart hidden: %+v %v", out, e)
	}
}

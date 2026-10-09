//go:build linux || darwin

package hostaction

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"golang.org/x/sys/unix"
)

// This entry point exists only in the test executable. The shipped command and
// its production dispatcher have no environment switch or injected handler.
func TestHostActionProcessChild(t *testing.T) {
	path := os.Getenv("VSK_TEST_ACTION_PROCESS_CONFIG")
	if path == "" {
		return
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		os.Exit(91)
	}
	var c actionProcessConfig
	if json.Unmarshal(raw, &c) != nil {
		os.Exit(92)
	}
	receipts, err := OpenReceipts(c.Root, uint32(os.Geteuid()))
	if err != nil {
		os.Exit(93)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	signal.Ignore(unix.SIGXFSZ)
	if c.Mode == "claim-write-failure" {
		if unix.Setrlimit(unix.RLIMIT_FSIZE, &unix.Rlimit{Cur: 0, Max: 0}) != nil {
			os.Exit(94)
		}
	}
	if c.Mode == "claim-sync-failure" {
		if processSyncFault(receipts) != nil {
			os.Exit(96)
		}
	}
	if c.Mode == "read-ready" {
		if os.WriteFile(c.Stage, []byte("ready"), 0600) != nil {
			os.Exit(97)
		}
	}
	h := actionProcessHandler{c: c, receipts: receipts}
	err = RunOnce(ctx, os.Stdin, os.Stdout, c.Policy, receipts, testDispatcher{h}, func() time.Time { return c.Now }, rand.Reader)
	if err == nil && c.Mode == "after-result" {
		h.pause(ctx, "result")
	}
	_ = receipts.Close()
	if err != nil {
		os.Exit(10)
	}
	os.Exit(0)
}

type actionProcessConfig struct {
	Root, Effect, Stage, Mode string
	Policy                    Policy
	Now                       time.Time
}

var processSyncFault = func(*Receipts) error { return fmt.Errorf("sync fault unavailable on this test platform") }

type actionProcessHandler struct {
	c        actionProcessConfig
	receipts *Receipts
}

func (h actionProcessHandler) pause(ctx context.Context, stage string) {
	if os.WriteFile(h.c.Stage, []byte(stage), 0600) != nil {
		os.Exit(95)
	}
	<-ctx.Done()
}
func (h actionProcessHandler) Execute(ctx context.Context, b generated.HostActionBundle) (generated.HostActionResult, error) {
	if h.c.Mode == "after-claim" {
		h.pause(ctx, "claim")
		return generated.HostActionResult{}, ctx.Err()
	}
	f, err := os.OpenFile(h.c.Effect, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return generated.HostActionResult{}, err
	}
	_, we := f.WriteString("effect\n")
	se := f.Sync()
	ce := f.Close()
	if we != nil || se != nil || ce != nil {
		return generated.HostActionResult{}, fmt.Errorf("effect persistence failed")
	}
	d, _ := BundleDigest(b)
	return generated.HostActionResult{Schema: generated.SchemaIDHostActionResult, SchemaVersion: "1.0.0", BundleDigest: d, ResultDigest: BytesDigest([]byte("effect\n")), Status: "succeeded", Changed: true, EffectObserved: true, Reason: "verified"}, nil
}
func (h actionProcessHandler) Verify(ctx context.Context, _ generated.HostActionBundle, _ generated.HostActionResult) error {
	if h.c.Mode == "after-effect" {
		h.pause(ctx, "effect")
		return ctx.Err()
	}
	if h.c.Mode == "result-sync-failure" {
		return processSyncFault(h.receipts)
	}
	if h.c.Mode == "result-write-failure" {
		return unix.Setrlimit(unix.RLIMIT_FSIZE, &unix.Rlimit{Cur: 0, Max: 0})
	}
	return nil
}

type actionProcess struct {
	keepInputOpen bool
	cmd           *exec.Cmd
	in            io.WriteCloser
	out           io.ReadCloser
	reader        *bufio.Reader
	done          chan error
}

func startActionProcess(t *testing.T, c actionProcessConfig) *actionProcess {
	t.Helper()
	raw, _ := json.Marshal(c)
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestHostActionProcessChild$")
	cmd.Env = append(os.Environ(), "VSK_TEST_ACTION_PROCESS_CONFIG="+path)
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &actionProcess{cmd: cmd, in: in, out: out, reader: bufio.NewReaderSize(out, MaximumEnvelope+2), done: make(chan error, 1)}
	go func() { p.done <- cmd.Wait() }()
	t.Cleanup(func() { _ = in.Close(); _ = out.Close(); _ = cmd.Process.Kill() })
	return p
}
func (p *actionProcess) wait(t *testing.T) error {
	t.Helper()
	select {
	case err := <-p.done:
		return err
	case <-time.After(5 * time.Second):
		_ = p.cmd.Process.Kill()
		t.Fatal("test helper failed to terminate")
		return nil
	}
}
func (p *actionProcess) frame(t *testing.T) []byte {
	t.Helper()
	type answer struct {
		raw []byte
		err error
	}
	ch := make(chan answer, 1)
	go func() { raw, err := ReadFrame(p.reader, MaximumFrame); ch <- answer{raw, err} }()
	select {
	case a := <-ch:
		if a.err != nil {
			t.Fatal(a.err)
		}
		return a.raw
	case <-time.After(5 * time.Second):
		_ = p.cmd.Process.Kill()
		t.Fatal("helper frame timed out")
		return nil
	}
}
func (p *actionProcess) authorize(t *testing.T, b generated.HostActionBundle, policy Policy, key ed25519.PrivateKey, now time.Time, tail string) {
	t.Helper()
	raw, err := SignEnvelope(b, policy.KeyID, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.in.Write(append(raw, '\n')); err != nil {
		t.Fatal(err)
	}
	var c generated.HostActionChallenge
	if json.Unmarshal(p.frame(t), &c) != nil {
		t.Fatal("bad challenge")
	}
	a := generated.HostActionAuthorization{Schema: generated.SchemaIDHostActionAuthorization, SchemaVersion: "1.0.0", BundleDigest: c.BundleDigest, ChallengeDigest: Digest(c), KeyID: policy.KeyID, AuthorizedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(5 * time.Second).Format(time.RFC3339), StateRevision: b.StateRevision, RecoveryEpoch: b.RecoveryEpoch}
	a.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, AuthorizationMessage(a)))
	if strings.HasPrefix(tail, "@") {
		raw := []byte("{bad}\n")
		if tail == "@oversized" {
			raw = bytes.Repeat([]byte("x"), MaximumFrame+2)
		}
		if tail == "@truncated" {
			raw = []byte(`{"schema":`)
		}
		_, _ = p.in.Write(raw)
		_ = p.in.Close()
		return
	}
	if err = WriteFrame(p.in, a, MaximumFrame); err != nil {
		t.Fatal(err)
	}
	if tail != "" {
		_, _ = io.WriteString(p.in, tail)
	}
	if !p.keepInputOpen {
		_ = p.in.Close()
	}
}
func processFixture(t *testing.T) (actionProcessConfig, generated.HostActionBundle, ed25519.PrivateKey) {
	t.Helper()
	b, p, key, now := fixtureBundle(t)
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	return actionProcessConfig{Root: root, Effect: filepath.Join(root, "effects"), Stage: filepath.Join(root, "stage"), Policy: p, Now: now}, b, key
}
func processEffects(t *testing.T, c actionProcessConfig, want int) {
	t.Helper()
	raw, err := os.ReadFile(c.Effect)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if string(raw) != strings.Repeat("effect\n", want) {
		t.Fatalf("effects=%q want %d", raw, want)
	}
}
func processStage(t *testing.T, c actionProcessConfig, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		raw, _ := os.ReadFile(c.Stage)
		if string(raw) == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("process did not reach " + want)
}
func processRetryDenied(t *testing.T, c actionProcessConfig, b generated.HostActionBundle, key ed25519.PrivateKey, want int) {
	t.Helper()
	c.Mode = ""
	c.Now = c.Now.Add(time.Second)
	b.IssuedAt = c.Now.Format(time.RFC3339)
	b.ExpiresAt = c.Now.Add(time.Minute).Format(time.RFC3339)
	b.LeaseID = "replacement-lease"
	p := startActionProcess(t, c)
	p.authorize(t, b, c.Policy, key, c.Now, "")
	if p.wait(t) == nil {
		t.Fatal("consumed execution replayed in a fresh process")
	}
	processEffects(t, c, want)
}
func TestHostActionProcessCrashAndDurableReplay(t *testing.T) {
	for _, mode := range []string{"after-claim", "after-effect", "after-result"} {
		for _, graceful := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/graceful=%t", mode, graceful), func(t *testing.T) {
				c, b, key := processFixture(t)
				c.Mode = mode
				p := startActionProcess(t, c)
				p.authorize(t, b, c.Policy, key, c.Now, "")
				stage := strings.TrimPrefix(mode, "after-")
				if mode == "after-result" {
					_ = p.frame(t)
				}
				processStage(t, c, stage)
				if graceful {
					_ = p.cmd.Process.Signal(os.Interrupt)
				} else {
					_ = p.cmd.Process.Kill()
				}
				_ = p.wait(t)
				want := 1
				if mode == "after-claim" {
					want = 0
				}
				processEffects(t, c, want)
				marker, err := os.ReadFile(filepath.Join(c.Root, ExecutionDigest(b)[7:]+".json"))
				if err != nil || len(marker) == 0 {
					t.Fatal("durable consumed marker lost", err)
				}
				processRetryDenied(t, c, b, key, want)
			})
		}
	}
}
func TestHostActionProcessConcurrentClaim(t *testing.T) {
	c, b, key := processFixture(t)
	first := startActionProcess(t, c)
	second := startActionProcess(t, c)
	first.keepInputOpen = true
	second.keepInputOpen = true
	first.authorize(t, b, c.Policy, key, c.Now, "")
	second.authorize(t, b, c.Policy, key, c.Now, "")
	processEffects(t, c, 0) // Both processes have valid authorization but are held before claim by EOF.
	_ = first.in.Close()
	_ = second.in.Close()
	// Drain both outputs while processes close. Only the winner has a result.
	_, _ = io.Copy(io.Discard, first.out)
	_, _ = io.Copy(io.Discard, second.out)
	a, e := first.wait(t), second.wait(t)
	if (a == nil) == (e == nil) {
		t.Fatalf("expected one winner, got %v %v", a, e)
	}
	processEffects(t, c, 1)
	processRetryDenied(t, c, b, key, 1)
}
func TestHostActionProcessPersistenceFailures(t *testing.T) {
	for _, mode := range []string{"claim-write-failure", "result-write-failure", "partial-claim", "claim-path-collision"} {
		t.Run(mode, func(t *testing.T) {
			c, b, key := processFixture(t)
			c.Mode = mode
			marker := filepath.Join(c.Root, ExecutionDigest(b)[7:]+".json")
			if mode == "partial-claim" {
				if err := os.WriteFile(marker, []byte(`{"bundleDigest":`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "claim-path-collision" {
				if err := os.Mkdir(marker, 0700); err != nil {
					t.Fatal(err)
				}
			}
			p := startActionProcess(t, c)
			p.authorize(t, b, c.Policy, key, c.Now, "")
			if p.wait(t) == nil {
				t.Fatal("persistence failure reported success")
			}
			want := 0
			if mode == "result-write-failure" {
				want = 1
			}
			processEffects(t, c, want)
			if _, err := os.Lstat(marker); err != nil {
				t.Fatal("uncertain consumed marker removed", err)
			}
			processRetryDenied(t, c, b, key, want)
		})
	}
}
func TestHostActionProcessRejectsBadFrames(t *testing.T) {
	for _, mode := range []string{"malformed", "oversized", "truncated", "trailing", "malformed-auth", "oversized-auth", "truncated-auth"} {
		t.Run(mode, func(t *testing.T) {
			c, b, key := processFixture(t)
			p := startActionProcess(t, c)
			if strings.HasSuffix(mode, "-auth") {
				p.authorize(t, b, c.Policy, key, c.Now, "@"+strings.TrimSuffix(mode, "-auth"))
			} else if mode == "trailing" {
				p.authorize(t, b, c.Policy, key, c.Now, "{}\n")
			} else {
				raw := []byte("{bad}\n")
				if mode == "oversized" {
					raw = bytes.Repeat([]byte("x"), MaximumEnvelope+2)
				}
				if mode == "truncated" {
					raw = []byte(`{"schema":`)
				}
				_, _ = p.in.Write(raw)
				_ = p.in.Close()
			}
			if p.wait(t) == nil {
				t.Fatal("invalid frame accepted")
			}
			processEffects(t, c, 0)
			if _, err := os.Stat(filepath.Join(c.Root, ExecutionDigest(b)[7:]+".json")); !os.IsNotExist(err) {
				t.Fatal("invalid frame consumed execution")
			}
		})
	}
}
func TestHostActionProcessInterruptedTransport(t *testing.T) {
	for _, mode := range []string{"read", "challenge-output", "result-output"} {
		t.Run(mode, func(t *testing.T) {
			c, b, key := processFixture(t)
			if mode == "read" {
				c.Mode = "read-ready"
			}
			p := startActionProcess(t, c)
			switch mode {
			case "read":
				processStage(t, c, "ready")
				if err := p.cmd.Process.Signal(os.Interrupt); err != nil {
					t.Fatal(err)
				}
			case "challenge-output":
				_ = p.out.Close()
				raw, _ := SignEnvelope(b, c.Policy.KeyID, key)
				_, _ = p.in.Write(append(raw, '\n'))
				_ = p.in.Close()
			case "result-output":
				p.authorize(t, b, c.Policy, key, c.Now, "")
				_ = p.out.Close()
			}
			_ = p.wait(t)
			if mode != "result-output" {
				processEffects(t, c, 0)
			} else {
				processEffects(t, c, 1)
				processRetryDenied(t, c, b, key, 1)
			}
		})
	}
}

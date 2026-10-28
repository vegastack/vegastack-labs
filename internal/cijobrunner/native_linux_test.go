//go:build linux

package cijobrunner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/cijobguard"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

// Explicit opt-in: public synthetic token only, networknone, real production
// entry/configure path. This is NOT successful GitHub registration/admission.
func TestNativeOfflineProductionBootstrapFailure(t *testing.T) {
	if os.Getenv("VSK_CI_RUNTIME_NATIVE") != "1" {
		t.Skip("requires named disposable rootless Docker environment")
	}
	binary := os.Getenv("VSK_CI_RUNTIME_BINARY")
	socket := os.Getenv("VSK_CI_RUNTIME_SOCKET")
	docker := os.Getenv("VSK_CI_RUNTIME_DOCKER")
	hash, e := fileDigest(binary)
	if e != nil {
		t.Fatal(e)
	}
	hook := sha256.Sum256([]byte(HookScript))
	p := RuntimeProfile{ImageIndexDigest: "sha256:" + Image[len(Image)-64:], ExecutableDigest: hash, HookDigest: "sha256:" + hex.EncodeToString(hook[:]), NetworkID: "none", DaemonUID: uint32(os.Geteuid()), MemoryBytes: 256 << 20, CPUQuotaMicros: 50000, CPUPeriodMicros: 100000, PidsLimit: 64, Offline: true}
	d, e := NewDocker(DockerConfig{ExecutablePath: docker, SocketPath: socket, VSKPath: binary}, p, nil)
	if e != nil {
		t.Fatal(e)
	}
	s := Spec{Binding: LaunchBinding{LifecycleID: "native-offline", RunID: "312", PlanID: "plan-312", LeaseID: "lease-312", Attempt: 1}, Deadline: time.Now().Add(45 * time.Second), RuntimeProfileID: "offline", RuntimeDigest: ComputeRuntimeDigest(p), Organization: "vegastack", RunnerName: "vsk-public-synthetic", RunnerGroup: "Default", Labels: []string{"vsk-public-synthetic"}}
	session := &nativeSession{}
	r, e := d.Run(context.Background(), s, session)
	t.Logf("real Configure failure=%v stage=%s registeredInput=%v stopped=%v removed=%v events=%v cleanup=%+v", e, r.Stage, session.token, r.Stopped, r.VolumesRemoved, session.events, r.Cleanup)
	if e == nil || !r.Stopped || !r.VolumesRemoved || !session.token || session.held || session.bootstrapStage != "registration_secret_delivered" || r.Stage != "registration_secret_delivered" {
		t.Fatal("production bootstrap failure/cleanup not established")
	}
}

type nativeSession struct {
	token, held    bool
	bootstrapStage string
	events         []string
}

func (s *nativeSession) Registration(context.Context) (*credentialref.Value, error) {
	s.token = true
	return credentialref.NewValue([]byte("vsk-public-synthetic-not-a-real-token"))
}
func (s *nativeSession) Configured(_ context.Context, r ConfiguredRunner) error {
	s.bootstrapStage = r.Stage
	if r.Stage != "registration_secret_delivered" || r.RunnerID != 0 {
		return ErrProtocol
	}
	return nil
}
func (s *nativeSession) Held(context.Context) (cijobguard.Decision, error) {
	s.held = true
	return cijobguard.Decision{}, ErrBlocked
}
func (s *nativeSession) Event(_ context.Context, e LifecycleEvent) error {
	s.events = append(s.events, fmt.Sprintf("%s:%d", e.Stage, e.ExitCode))
	return nil
}

// Root opt-in exercises the real fixed self-exec UID/GID bridge. Configuration
// is protected test input, not installed host configuration or live authority.
func TestNativeRootWorkerBootstrapFailure(t *testing.T) {
	testNativeRootWorkerBootstrapFailure(t, false)
}

// This proves the real inherited verifier channel and online checks, using
// only an invalid public token. It is not registration or Worker admission.
func TestNativeRootWorkerOnlineBootstrapFailure(t *testing.T) {
	if os.Getenv("VSK_CI_RUNTIME_NETWORK_CONFIG") == "" {
		t.Skip("explicit protected public/synthetic online network fixture required")
	}
	testNativeRootWorkerBootstrapFailure(t, true)
}

func testNativeRootWorkerBootstrapFailure(t *testing.T, online bool) {
	t.Helper()
	if os.Getenv("VSK_CI_RUNTIME_ROOT_BRIDGE") != "1" {
		t.Skip("requires named disposable root parent")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root parent required")
	}
	binary := os.Getenv("VSK_CI_RUNTIME_BINARY")
	hash, e := fileDigest(binary)
	if e != nil {
		t.Fatal(e)
	}
	hook := sha256.Sum256([]byte(HookScript))
	p := RuntimeProfile{ImageIndexDigest: "sha256:" + Image[len(Image)-64:], ExecutableDigest: hash, HookDigest: "sha256:" + hex.EncodeToString(hook[:]), NetworkID: "none", DaemonUID: 505, MemoryBytes: 256 << 20, CPUQuotaMicros: 50000, CPUPeriodMicros: 100000, PidsLimit: 64, Offline: true}
	c := NativeConfig{ProfileID: "offline", RuntimeDigest: ComputeRuntimeDigest(p), HostID: "synthetic-host", HostIdentityDigest: "sha256:" + strings.Repeat("a", 64), DaemonGID: 505, Docker: DockerConfig{ExecutablePath: os.Getenv("VSK_CI_RUNTIME_DOCKER"), SocketPath: os.Getenv("VSK_CI_RUNTIME_SOCKET"), VSKPath: binary}, Profile: p}
	if online {
		raw, e := os.ReadFile(os.Getenv("VSK_CI_RUNTIME_NETWORK_CONFIG"))
		if e != nil {
			t.Fatal(e)
		}
		var network NativeConfig
		if decodeFrame(context.Background(), raw, &network) != nil || network.Network == nil {
			t.Fatal("invalid explicit network fixture")
		}
		// Preserve independently measured executable, hook, daemon identity and
		// resource bounds; the fixture supplies only protected networking inputs.
		p.DNSResolver = network.Profile.DNSResolver
		p.NetworkID = network.Profile.NetworkID
		p.NetworkEvidenceDigest = network.Profile.NetworkEvidenceDigest
		p.Offline = false
		c.Network = network.Network
		c.Profile = p
		c.RuntimeDigest = ComputeRuntimeDigest(p)
	}
	now := time.Now().UTC().Truncate(time.Second)
	spec := Spec{Binding: LaunchBinding{LifecycleID: "root-native", RunID: "312", PlanID: "plan-312", LeaseID: "lease-312", Attempt: 1}, Deadline: now.Add(45 * time.Second), RuntimeProfileID: c.ProfileID, RuntimeDigest: c.RuntimeDigest, Organization: "vegastack", RunnerName: "vsk-public-synthetic", RunnerGroup: "Default", Labels: []string{"vsk-public-synthetic"}}
	raw, _ := json.Marshal(spec)
	b := generated.HostActionBundle{Schema: generated.SchemaIDHostActionBundle, SchemaVersion: "1.0.0", ActionID: hostaction.CIJobAction, ActionVersion: "1.0.0", ActionInput: string(raw), ActionInputDigest: hostaction.BytesDigest(raw), BundleID: "bundle-312", PlanID: "plan-312", PlanDigest: c.HostIdentityDigest, RunID: "run-312", StepID: "step-312", LeaseID: "lease-312", HostID: c.HostID, HostIdentityDigest: c.HostIdentityDigest, DeclarationID: "declaration-312", DeclarationRevision: 1, StateRevision: 1, RecoveryEpoch: 0, AutomationPrincipalID: "automation-312", CallerUID: 505, CredentialReferenceID: "credential-312", CredentialMaterialVersion: "version-312", ConsoleConfirmationDigest: c.HostIdentityDigest, IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339)}
	input, send := io.Pipe()
	receive, output := io.Pipe()
	defer send.Close()
	defer receive.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		r, e := (&nativeBridge{config: c, executable: binary}).ExecuteCI(ctx, b, input, output)
		if e == nil && (r.Status != "partial" || !r.EffectObserved) {
			e = ErrBlocked
		}
		output.Close()
		done <- e
	}()
	control := NewControl(receive, send)
	stage := ""
	var completion *Completion
	events := []LifecycleEvent{}
	for {
		m, e := control.Receive(ctx)
		if e != nil {
			t.Fatal(e)
		}
		switch m.Kind {
		case "ready":
			v, _ := credentialref.NewValue([]byte("vsk-public-synthetic-not-a-real-token"))
			e = control.WriteRegistration(ctx, v)
			v.Close()
			if e != nil {
				t.Fatal(e)
			}
		case "configured":
			stage = m.Runner.Stage
		case "held":
			t.Fatal("public fake token reached HELD")
		case "event":
			events = append(events, *m.Event)
		case "complete":
			completion = m.Completion
		}
		if completion != nil {
			break
		}
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	want, e := LifecycleEventDigest(events)
	if e != nil || completion.LogDigest != want || completion.Succeeded || !completion.Stopped || !completion.VolumesRemoved || stage != "registration_secret_delivered" {
		t.Fatalf("bad root worker result stage=%s completion=%+v events=%v", stage, completion, events)
	}
	t.Logf("PASS actual demoted worker, online=%v, real Configure failure stage, fixed event digest and verified cleanup; no provider registration", online)
}

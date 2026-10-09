package hostaction

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	protocol "github.com/vegastack/vegastack-labs/internal/hostaction"
	"golang.org/x/crypto/ssh"
)

type targetFixture struct {
	target  Target
	calls   int
	changed bool
}

func (s *targetFixture) Resolve(context.Context, generated.HostActionBundle) (Target, error) {
	s.calls++
	v := s.target
	if s.changed && s.calls > 1 {
		v.Revision++
	}
	return v, nil
}

type issuerFixture struct {
	envelope generated.HostActionEnvelope
	denied   bool
}

func (s issuerFixture) Issue(context.Context, adapter.Operation, adapter.ExactExecutionBinding) (generated.HostActionEnvelope, error) {
	if s.denied {
		return generated.HostActionEnvelope{}, denied()
	}
	return s.envelope, nil
}

type authorityFixture struct {
	calls  int
	key    ed25519.PrivateKey
	reject bool
}

func (a *authorityFixture) Authorize(_ context.Context, e generated.HostActionEnvelope, c generated.HostActionChallenge) (generated.HostActionAuthorization, error) {
	a.calls++
	if a.reject {
		return generated.HostActionAuthorization{}, denied()
	}
	now := time.Now().UTC().Truncate(time.Second)
	v := generated.HostActionAuthorization{Schema: generated.SchemaIDHostActionAuthorization, SchemaVersion: "1.0.0", BundleDigest: c.BundleDigest, ChallengeDigest: protocol.Digest(c), KeyID: e.KeyID, AuthorizedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(5 * time.Second).Format(time.RFC3339), StateRevision: e.Bundle.StateRevision, RecoveryEpoch: e.Bundle.RecoveryEpoch}
	v.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(a.key, protocol.AuthorizationMessage(v)))
	return v, nil
}
func fixture(t *testing.T, mode string) (*Adapter, adapter.Operation, adapter.ExactExecutionBinding, *credentialref.Value, *authorityFixture, *targetFixture, *atomic.Int32) {
	t.Helper()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(key)
	pk, _ := x509.MarshalPKCS8PrivateKey(key)
	value, err := credentialref.NewValue(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(value.Close)
	now := time.Now().UTC().Truncate(time.Second)
	d := "sha256:" + strings.Repeat("a", 64)
	b := generated.HostActionBundle{Schema: generated.SchemaIDHostActionBundle, SchemaVersion: "1.0.0", ActionID: "test.noop", ActionVersion: "1.0.0", ActionInput: "{}", ActionInputDigest: protocol.BytesDigest([]byte("{}")), BundleID: "bundle-a", PlanID: "plan-a", PlanDigest: d, RunID: "run-a", StepID: "step-a", LeaseID: "lease-a", HostID: "host-a", HostIdentityDigest: d, DeclarationID: "declaration-a", DeclarationRevision: 1, StateRevision: 2, RecoveryEpoch: 0, AutomationPrincipalID: "automation-a", CallerUID: 1001, CredentialReferenceID: "credential-a", CredentialMaterialVersion: "version-a", ConsoleConfirmationDigest: d, IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339)}
	raw, err := protocol.SignEnvelope(b, "key-a", key)
	if err != nil {
		t.Fatal(err)
	}
	var envelope generated.HostActionEnvelope
	_ = json.Unmarshal(raw, &envelope)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	connections := new(atomic.Int32)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		connections.Add(1)
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if !bytes.Equal(k.Marshal(), signer.PublicKey().Marshal()) {
				return nil, denied()
			}
			return nil, nil
		}}
		cfg.AddHostKey(signer)
		server, channels, requests, err := ssh.NewServerConn(conn, cfg)
		if err != nil {
			return
		}
		defer server.Close()
		go ssh.DiscardRequests(requests)
		for channel := range channels {
			if channel.ChannelType() != "session" {
				_ = channel.Reject(ssh.UnknownChannelType, "denied")
				continue
			}
			ch, reqs, err := channel.Accept()
			if err != nil {
				return
			}
			defer ch.Close()
			for req := range reqs {
				if req.Type != "exec" {
					_ = req.Reply(false, nil)
					continue
				}
				var commandRequest struct{ Command string }
				if ssh.Unmarshal(req.Payload, &commandRequest) != nil || commandRequest.Command != command {
					_ = req.Reply(false, nil)
					return
				}
				_ = req.Reply(true, nil)
				reader := bufio.NewReaderSize(ch, protocol.MaximumEnvelope+2)
				r, err := protocol.ReadFrame(reader, protocol.MaximumEnvelope)
				if err != nil {
					return
				}
				var e generated.HostActionEnvelope
				if json.Unmarshal(r, &e) != nil {
					return
				}
				digest, _ := protocol.BundleDigest(e.Bundle)
				c := generated.HostActionChallenge{Schema: generated.SchemaIDHostActionChallenge, SchemaVersion: "1.0.0", BundleDigest: digest, Nonce: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)), HostID: b.HostID, StartedAt: time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)}
				if mode == "wrong-challenge" {
					c.HostID = "other"
				}
				if mode == "oversize" {
					_, _ = ch.Write(bytes.Repeat([]byte{'x'}, protocol.MaximumFrame+3))
					return
				}
				if protocol.WriteFrame(ch, c, protocol.MaximumFrame) != nil {
					return
				}
				r, err = protocol.ReadFrame(reader, protocol.MaximumFrame)
				if err != nil {
					return
				}
				var auth generated.HostActionAuthorization
				if json.Unmarshal(r, &auth) != nil {
					return
				}
				if _, err = reader.ReadByte(); err != io.EOF {
					return
				}
				policy := protocol.Policy{HostID: b.HostID, HostIdentityDigest: d, CallerUID: 1001, KeyID: "key-a", PublicKey: key.Public().(ed25519.PublicKey)}
				if protocol.VerifyAuthorization(r, c, b, policy, time.Now()) != nil {
					return
				}
				if mode == "disconnect" {
					return
				}
				result := generated.HostActionResult{Schema: generated.SchemaIDHostActionResult, SchemaVersion: "1.0.0", BundleDigest: digest, ResultDigest: d, Status: "succeeded", EffectObserved: true, Reason: "verified"}

				if mode == "measured" || mode == "tampered-measured" {
					for i := 0; i < 8; i++ {
						m := generated.AccessMeasurement{Schema: generated.SchemaIDAccessMeasurement, SchemaVersion: "1.0.0", ControlID: "control-" + strconv.Itoa(i), Kind: "ssh", Status: "passed", SubjectHostID: b.HostID, SubjectIdentityDigest: d, ProfileLockDigest: d, ProducerID: "debian-access", ProducerVersion: "1.0.0", BundleDigest: digest, ObservedAt: time.Now().UTC().Format(time.RFC3339), ConfigurationDigest: d, PositiveProbeDigest: d, NegativeProbeDigest: d, Reason: "measured"}
						m.Probe = &generated.AccessProbeObservation{Schema: generated.SchemaIDAccessProbeObservation, SchemaVersion: "1.0.0", ProbeID: m.ControlID, SourceHostID: "source-host", SourceIdentityDigest: d, SourceContextDigest: d, ActualSourceAddress: "127.0.0.1", SourceNamespaceDigest: d, DestinationDigest: d, WitnessDigest: d, Expected: "allowed", Actual: "allowed"}
						m.MeasurementDigest = protocol.MeasurementDigest(m)
						result.ControlMeasurements = append(result.ControlMeasurements, m)
					}
					result.ResultDigest = protocol.ResultDigest(result)
					if mode == "tampered-measured" {
						result.ControlMeasurements[0].Status = "failed"
					}
				}
				if mode == "wrong-result" {
					result.BundleDigest = protocol.BytesDigest([]byte("wrong"))
				}
				_ = protocol.WriteFrame(ch, result, protocol.MaximumResultFrame)
				if mode == "trailing" {
					_, _ = ch.Write([]byte("extra\n"))
				}
				_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
				return
			}
		}
	}()
	target := &targetFixture{target: Target{HostID: b.HostID, HostIdentityDigest: d, Address: "127.0.0.1", Port: uint16(listener.Addr().(*net.TCPAddr).Port), User: "automation", HostKey: string(ssh.MarshalAuthorizedKey(signer.PublicKey())), AutomationPrincipalID: b.AutomationPrincipalID, CallerUID: 1001, Revision: 1}}
	auth := &authorityFixture{key: key}
	a, err := New(target, issuerFixture{envelope: envelope}, auth)
	if err != nil {
		t.Fatal(err)
	}
	op := adapter.Operation{OperationID: "op-a", OperationType: "host.action.execute", AdapterID: "host-action", ExecutorID: "central", TargetID: b.HostID, InputDigest: d, ArtifactDigest: d, SecretReferences: []adapter.SecretReference{{ID: b.CredentialReferenceID, Consumer: "host-action"}}}
	binding := adapter.ExactExecutionBinding{PlanID: b.PlanID, PlanDigest: b.PlanDigest, RunID: b.RunID, StepID: b.StepID, LeaseID: b.LeaseID, StateRevision: 2, MaximumExpiresAt: now.Add(2 * time.Minute).Format(time.RFC3339)}
	return a, op, binding, value, auth, target, connections
}
func TestBoundSSHProtocol(t *testing.T) {
	for _, mode := range []string{"success", "wrong-challenge", "oversize", "disconnect", "wrong-result", "trailing", "changed-target", "authority-denied", "wrong-host-key", "wrong-consumer", "expired", "issuer-denied"} {
		t.Run(mode, func(t *testing.T) {
			a, op, b, v, auth, target, connections := fixture(t, mode)
			switch mode {
			case "changed-target":
				target.changed = true
			case "authority-denied":
				auth.reject = true
			case "wrong-host-key":
				_, key, _ := ed25519.GenerateKey(rand.Reader)
				s, _ := ssh.NewSignerFromKey(key)
				target.target.HostKey = string(ssh.MarshalAuthorizedKey(s.PublicKey()))
			case "wrong-consumer":
				op.SecretReferences[0].Consumer = "preloaded-discovery"
			case "expired":
				b.MaximumExpiresAt = time.Now().Add(-time.Minute).Format(time.RFC3339)
			case "issuer-denied":
				a.bundles = issuerFixture{denied: true}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			effect, err := a.ExecuteBoundWithCredentials(ctx, op, b, []*credentialref.Value{v})
			if mode == "success" {
				if err != nil {
					t.Fatal(err)
				}
				verified, err := a.Verify(ctx, op, effect)
				if err != nil || !verified.Verified {
					t.Fatal("missing verification", err)
				}
				if _, err = a.Verify(ctx, op, effect); err == nil {
					t.Fatal("verification replay accepted")
				}
				return
			}
			if err == nil {
				t.Fatal("accepted denial case")
			}
			observed := mode == "disconnect" || mode == "wrong-result" || mode == "trailing"
			if effect.EffectObserved != observed {
				t.Fatalf("uncertainty=%v want%v", effect.EffectObserved, observed)
			}
			if mode == "wrong-consumer" || mode == "expired" || mode == "issuer-denied" {
				if connections.Load() != 0 {
					t.Fatal("denied request dialed")
				}
			}
			if mode == "wrong-challenge" || mode == "oversize" || mode == "changed-target" || mode == "wrong-host-key" {
				if auth.calls != 0 {
					t.Fatal("signed invalid challenge")
				}
			}
		})
	}
}

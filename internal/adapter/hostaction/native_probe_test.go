//go:build linux || darwin

package hostaction

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	protocol "github.com/vegastack/vegastack-labs/internal/hostaction"
	"golang.org/x/crypto/ssh"
)

type nativeProbeTarget struct{ target Target }

func (s nativeProbeTarget) Resolve(context.Context, generated.HostActionBundle) (Target, error) {
	return s.target, nil
}

type nativeProbeAuthority struct{ key ed25519.PrivateKey }

func (a nativeProbeAuthority) Authorize(_ context.Context, e generated.HostActionEnvelope, c generated.HostActionChallenge) (generated.HostActionAuthorization, error) {
	now := time.Now().UTC().Truncate(time.Second)
	v := generated.HostActionAuthorization{Schema: generated.SchemaIDHostActionAuthorization, SchemaVersion: "1.0.0", BundleDigest: c.BundleDigest, ChallengeDigest: protocol.Digest(c), KeyID: e.KeyID, AuthorizedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(5 * time.Second).Format(time.RFC3339), StateRevision: e.Bundle.StateRevision, RecoveryEpoch: e.Bundle.RecoveryEpoch}
	v.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(a.key, protocol.AuthorizationMessage(v)))
	return v, nil
}

type nativeReadHandler struct{ calls *atomic.Int32 }

func (h nativeReadHandler) Lookup(id, version string) (protocol.Handler, bool) {
	return h, id == "debian.access.collect" && version == "1.0.0"
}
func (h nativeReadHandler) Execute(_ context.Context, b generated.HostActionBundle) (generated.HostActionResult, error) {
	h.calls.Add(1)
	d, _ := protocol.BundleDigest(b)
	return generated.HostActionResult{Schema: generated.SchemaIDHostActionResult, SchemaVersion: "1.0.0", BundleDigest: d, ResultDigest: protocol.Digest("read observation"), Status: "succeeded", EffectObserved: true, Reason: "verified"}, nil
}
func (h nativeReadHandler) Verify(context.Context, generated.HostActionBundle, generated.HostActionResult) error {
	return nil
}

func TestNativeConcurrentProtocolUsesActualDurableClaimAndFreshReplay(t *testing.T) {
	// The dispatcher is a harmless software fixture; framing, signature checks,
	// independent SSH sessions and durable claims use production implementations.
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(key)
	now := time.Now().UTC().Truncate(time.Second)
	d := protocol.Digest("binding")
	b := generated.HostActionBundle{Schema: generated.SchemaIDHostActionBundle, SchemaVersion: "1.0.0", ActionID: "debian.access.collect", ActionVersion: "1.0.0", ActionInput: "{}", ActionInputDigest: protocol.BytesDigest([]byte("{}")), BundleID: "bundle-native", PlanID: "plan-native", PlanDigest: d, RunID: "run-native", StepID: "step-native", LeaseID: "lease-native", HostID: "host-native", HostIdentityDigest: d, DeclarationID: "declaration-native", DeclarationRevision: 1, StateRevision: 2, RecoveryEpoch: 0, AutomationPrincipalID: "automation-native", CallerUID: 1001, CredentialReferenceID: "credential-native", CredentialMaterialVersion: "version-native", ConsoleConfirmationDigest: d, IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339)}
	raw, err := protocol.SignEnvelope(b, "key-native", key)
	if err != nil {
		t.Fatal(err)
	}
	var envelope generated.HostActionEnvelope
	json.Unmarshal(raw, &envelope)
	root := t.TempDir()
	os.Chmod(root, 0700)
	receipts, err := protocol.OpenReceipts(root, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer receipts.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var calls atomic.Int32
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if !bytes.Equal(k.Marshal(), signer.PublicKey().Marshal()) {
			return nil, denied()
		}
		return nil, nil
	}}
	cfg.AddHostKey(signer)
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			conn, e := listener.Accept()
			if e != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(12 * time.Second))
				server, channels, requests, e := ssh.NewServerConn(conn, cfg)
				if e != nil {
					return
				}
				defer server.Close()
				go ssh.DiscardRequests(requests)
				for channel := range channels {
					ch, requests, e := channel.Accept()
					if e != nil {
						return
					}
					defer ch.Close()
					for request := range requests {
						var commandRequest struct{ Command string }
						if request.Type != "exec" || ssh.Unmarshal(request.Payload, &commandRequest) != nil || commandRequest.Command != command {
							request.Reply(false, nil)
							return
						}
						request.Reply(true, nil)
						policy := protocol.Policy{HostID: b.HostID, HostIdentityDigest: b.HostIdentityDigest, CallerUID: 1001, KeyID: envelope.KeyID, PublicKey: key.Public().(ed25519.PublicKey)}
						e = protocol.RunOnce(context.Background(), ch, ch, policy, receipts, nativeReadHandler{&calls}, time.Now, rand.Reader)
						status := uint32(0)
						if e != nil {
							status = 1
						}
						ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
						return
					}
				}
			}()
		}
	}()
	target := Target{HostID: b.HostID, HostIdentityDigest: b.HostIdentityDigest, Address: "127.0.0.1", Port: uint16(listener.Addr().(*net.TCPAddr).Port), User: "automation", HostKey: string(ssh.MarshalAuthorizedKey(signer.PublicKey())), CallerUID: 1001, AutomationPrincipalID: b.AutomationPrincipalID, Revision: 1}
	a, _ := New(nativeProbeTarget{target}, issuerFixture{envelope: envelope}, nativeProbeAuthority{key})
	pk, _ := x509.MarshalPKCS8PrivateKey(key)
	value, err := credentialref.NewValue(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}))
	if err != nil {
		t.Fatal(err)
	}
	defer value.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	digest, _ := protocol.BundleDigest(b)
	result, observed, err := a.exchangeNativeProbe(ctx, target, envelope, digest, value, "action-concurrency")
	if err != nil || !observed || result.Status != "succeeded" {
		t.Fatalf("protocol %v %v %+v", err, observed, result)
	}
	got, err := a.NativeProtocolObservationFor(b)
	if err != nil || got.CompletedResults != 1 || len(got.ConcurrentDenials) != 2 || got.ReplayDenial.Phase != "execution-claim" || calls.Load() != 1 {
		t.Fatalf("wrong evidence %+v calls=%d err=%v", got, calls.Load(), err)
	}
	altered := b
	altered.RecoveryEpoch++
	if _, err = a.NativeProtocolObservationFor(altered); err == nil {
		t.Fatal("observation transplanted")
	}
}

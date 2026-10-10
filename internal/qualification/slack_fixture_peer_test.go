package qualification

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/adapters/slack"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

type fixtureSlackCredential struct{ app, bot []byte }

func (f fixtureSlackCredential) Resolve(_ context.Context, r credentialref.Reference) ([]byte, error) {
	if r.ID == "app" {
		return append([]byte{}, f.app...), nil
	}
	return append([]byte{}, f.bot...), nil
}

func fixturePeerTest(t *testing.T) (*slackFixturePeer, *http.Client, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	now := time.Now().UTC().Truncate(time.Second)
	p := &slackFixturePeer{scope: generated.NativeSlackFixtureScope{IssuedAt: now.Add(-time.Minute).Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), WorkspaceID: "TNATIVE", UserID: "UNATIVE", ChannelID: "CNATIVE", ApproveActionID: "approve", RejectActionID: "reject", SetupPlanID: "setup-exact", SetupPlanDigest: hostaction.Digest("setup")}, appToken: []byte("synthetic-test-app"), botToken: []byte("synthetic-test-bot"), clock: time.Now, ctx: ctx, tickets: map[string]time.Time{}, used: map[string]bool{}, queue: make(chan []byte, 16)}
	p.approvals = func() (generated.NativeSlackFixtureApprovalList, error) {
		return generated.NativeSlackFixtureApprovalList{Schema: generated.SchemaIDNativeSlackFixtureApprovalList, SchemaVersion: "1.0.0", Approvals: []generated.NativeSlackFixtureApproval{}}, nil
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "isolated-slack-fixture"}, DNSNames: []string{"slack.com", "wss-native.slack.com"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(2 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyBytes, _ := x509.MarshalPKCS8PrivateKey(key)
	pair, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(p)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13}
	server.StartTLS()
	roots := x509.NewCertPool()
	leaf, _ := x509.ParseCertificate(der)
	roots.AddCert(leaf)
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}}
	t.Cleanup(func() { cancel(); tr.CloseIdleConnections(); server.Close() })
	return p, &http.Client{Transport: tr, Timeout: 5 * time.Second}, cancel
}
func TestNativeSlackFixtureUsesActualAdapterAndExactAllowlist(t *testing.T) {
	p, client, cancel := fixturePeerTest(t)
	transport, err := slack.NewHTTPTransport(client)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	d := hostaction.Digest("exact-native-plan")
	card := acknowledgement.RequestCard{ReviewText: "Synthetic isolated native plan", Nonce: "synthetic-unique-nonce-with-at-least-32-bytes", Request: generated.AcknowledgementRequest{PlanID: "plan-native", PlanDigest: d, TargetDigest: d, ReasonDigest: d, StateRevision: 2, RecoveryEpoch: 0, ExpiresAt: now.Add(time.Minute).Format(time.RFC3339)}}
	allowed := generated.NativeSlackFixtureApproval{Schema: generated.SchemaIDNativeSlackFixtureApproval, SchemaVersion: "1.0.0", PlanID: card.Request.PlanID, PlanDigest: d, TargetDigest: d, ReasonDigest: d, StateRevision: 2, ExpiresAt: card.Request.ExpiresAt, Action: "approve"}
	p.approvals = func() (generated.NativeSlackFixtureApprovalList, error) {
		return generated.NativeSlackFixtureApprovalList{Schema: generated.SchemaIDNativeSlackFixtureApprovalList, SchemaVersion: "1.0.0", Approvals: []generated.NativeSlackFixtureApproval{allowed}}, nil
	}
	candidates := make(chan acknowledgement.Candidate, 1)
	adapter, err := slack.NewAdapter(slack.Config{AppTokenReference: credentialref.Reference{ID: "app", Consumer: "slack-acknowledgement"}, BotTokenReference: credentialref.Reference{ID: "bot", Consumer: "slack-acknowledgement"}, WorkspaceID: p.scope.WorkspaceID, SlackUserID: p.scope.UserID, HumanID: "human-native", AuthorityID: "authority-native", ChannelID: p.scope.ChannelID, ApproveActionID: "approve", RejectActionID: "reject", ReconnectDelay: time.Millisecond, MaxReconnectDelay: time.Second}, fixtureSlackCredential{p.appToken, p.botToken}, transport, slack.CandidateSinkFuncs{SubmitFunc: func(_ context.Context, c acknowledgement.Candidate) error { candidates <- c; return nil }, RejectFunc: func(context.Context, acknowledgement.AdapterRejection) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- adapter.Run(p.ctx) }()
	wrong := card
	wrong.Request.PlanDigest = hostaction.Digest("changed")
	if adapter.Publish(p.ctx, wrong) == nil {
		t.Fatal("unlisted exact plan accepted")
	}
	if err := adapter.Publish(p.ctx, card); err != nil {
		t.Fatal(err)
	}
	select {
	case c := <-candidates:
		if c.PlanID != card.Request.PlanID || c.PlanDigest != d || c.Nonce != card.Nonce || c.Human.ID != "human-native" || c.Action != acknowledgement.ActionApprove {
			t.Fatal("wrong decoded candidate")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("actual Slack adapter did not ingest fixture websocket")
	}
	if adapter.Publish(p.ctx, card) == nil {
		t.Fatal("already consumed exact plan republished")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("fixture adapter shutdown exceeded bound")
	}
}
func TestNativeSlackFixtureRejectsExpiredAndChangedBindings(t *testing.T) {
	p, _, _ := fixturePeerTest(t)
	d := hostaction.Digest("scope")
	a := generated.NativeSlackFixtureApproval{Schema: generated.SchemaIDNativeSlackFixtureApproval, SchemaVersion: "1.0.0", PlanID: "plan", PlanDigest: d, TargetDigest: d, ReasonDigest: d, StateRevision: 2, ExpiresAt: time.Now().UTC().Add(time.Minute).Truncate(time.Second).Format(time.RFC3339), Action: "reject"}
	p.approvals = func() (generated.NativeSlackFixtureApprovalList, error) {
		return generated.NativeSlackFixtureApprovalList{Schema: generated.SchemaIDNativeSlackFixtureApprovalList, SchemaVersion: "1.0.0", Approvals: []generated.NativeSlackFixtureApproval{a}}, nil
	}
	good := fixtureActionBinding{PlanID: a.PlanID, PlanDigest: d, TargetDigest: d, ReasonDigest: d, StateRevision: 2, ExpiresAt: a.ExpiresAt}
	if action, err := p.allowed(good); err != nil || action != "reject" {
		t.Fatal("exact rejection selection", action, err)
	}
	for _, kind := range []string{"target", "reason", "revision", "epoch", "expired", "duplicate"} {
		t.Run(kind, func(t *testing.T) {
			b := good
			switch kind {
			case "target":
				b.TargetDigest = hostaction.Digest("other")
			case "reason":
				b.ReasonDigest = hostaction.Digest("other")
			case "revision":
				b.StateRevision++
			case "epoch":
				b.RecoveryEpoch++
			case "expired":
				b.ExpiresAt = time.Now().Add(-time.Second).UTC().Format(time.RFC3339)
			case "duplicate":
				old := p.approvals
				defer func() { p.approvals = old }()
				p.approvals = func() (generated.NativeSlackFixtureApprovalList, error) {
					return generated.NativeSlackFixtureApprovalList{Schema: generated.SchemaIDNativeSlackFixtureApprovalList, SchemaVersion: "1.0.0", Approvals: []generated.NativeSlackFixtureApproval{a, a}}, nil
				}
			}
			if _, err := p.allowed(b); err == nil {
				t.Fatal("changed or ambiguous authority accepted")
			}
		})
	}
}

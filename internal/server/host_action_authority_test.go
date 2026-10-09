package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/store"
	"strings"
	"testing"
	"time"
)

func TestActionAuthorityRequiresIndependentSigner(t *testing.T) {
	if _, err := NewHostActionAuthority(nil, nil, time.Now); err == nil {
		t.Fatal("missing signer/store accepted")
	}
}

type actionTestSigner struct {
	key   ed25519.PrivateKey
	calls int
}

func (s *actionTestSigner) Sign(_ context.Context, b []byte) ([]byte, error) {
	s.calls++
	return ed25519.Sign(s.key, b), nil
}
func (s *actionTestSigner) PublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), s.key[32:]...)
}
func (s *actionTestSigner) KeyID() string { return "key-a" }

type actionTestSource struct {
	x   store.HostActionExecution
	err error
}

func (s *actionTestSource) CurrentExecution(context.Context, adapter.Operation, adapter.ExactExecutionBinding) (store.HostActionExecution, error) {
	return s.x, s.err
}
func (s *actionTestSource) ExecutionForBundle(context.Context, generated.HostActionBundle) (store.HostActionExecution, error) {
	return s.x, s.err
}
func TestHostActionIssuerAuthorizerFreezesEnvelopeAndRechecksState(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := &actionTestSigner{key: key}
	at := time.Date(2026, 10, 9, 7, 0, 0, 0, time.UTC)
	now := at
	digest := "sha256:" + strings.Repeat("a", 64)
	req := generated.HostActionRequest{Schema: generated.SchemaIDHostActionRequest, SchemaVersion: "1.0.0", ActionID: "test.write-file", ActionVersion: "1.0.0", ActionInput: "{}", ActionInputDigest: hostaction.BytesDigest([]byte("{}")), HostID: "host-a", TargetRevision: 1, TargetDigest: digest, AutomationPrincipalID: "automation-a", CallerUID: 1001, CredentialReferenceID: "credential-a", CredentialMaterialVersion: "version-a", ConsoleConfirmation: generated.HostActionConsoleConfirmation{Schema: generated.SchemaIDHostActionConsoleConfirmation, SchemaVersion: "1.0.0", Method: "administrator-verified-console", TargetDigest: digest, HostIdentityDigest: digest}, ExpectedStateRevision: 1, RecoveryEpoch: 0, IdempotencyKey: "request-a"}
	source := &actionTestSource{x: store.HostActionExecution{Draft: store.HostActionDraft{Request: req, Digest: hostaction.Digest(req)}, Plan: generated.Plan{PlanID: "plan-a", PlanDigest: digest, DeclarationID: "declaration-a", ExpiresAt: at.Add(time.Minute).Format(time.RFC3339), Binding: generated.PlanBinding{DeclarationRevision: 1, StateRevision: 3}}, Run: generated.Run{RunID: "run-a"}, Step: generated.RunStep{StepID: "step-a"}, Lease: generated.ExecutorLease{LeaseID: "lease-a", LeaseExpiresAt: at.Add(time.Minute).Format(time.RFC3339), MaximumExpiresAt: at.Add(time.Minute).Format(time.RFC3339)}}}
	issuer := &HostActionBundleIssuer{Repository: source, Signer: signer, Clock: func() time.Time { return now }}
	envelope, err := issuer.Issue(context.Background(), adapter.Operation{}, adapter.ExactExecutionBinding{})
	if err != nil {
		t.Fatal(err)
	}
	now = at.Add(time.Second)
	bundleDigest, _ := hostaction.BundleDigest(envelope.Bundle)
	challenge := generated.HostActionChallenge{Schema: generated.SchemaIDHostActionChallenge, SchemaVersion: "1.0.0", BundleDigest: bundleDigest, Nonce: base64.StdEncoding.EncodeToString(make([]byte, 32)), HostID: req.HostID, StartedAt: now.Format(time.RFC3339)}
	authority := &HostActionAuthority{repository: source, signer: signer, now: func() time.Time { return now }}
	approved, err := authority.Authorize(context.Background(), envelope, challenge)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(approved)
	policy := hostaction.Policy{HostID: req.HostID, HostIdentityDigest: digest, CallerUID: 1001, KeyID: signer.KeyID(), PublicKey: signer.PublicKey()}
	if err := hostaction.VerifyAuthorization(raw, challenge, envelope.Bundle, policy, now); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"revoked", "shorter-lease", "changed-identity", "tampered-signature"} {
		t.Run(scenario, func(t *testing.T) {
			before := signer.calls
			saved := source.x
			savedEnvelope := envelope
			switch scenario {
			case "revoked":
				source.err = actionFailure()
			case "shorter-lease":
				source.x.Lease.LeaseExpiresAt = now.Add(time.Second).Format(time.RFC3339)
			case "changed-identity":
				source.x.Draft.Request.ConsoleConfirmation.HostIdentityDigest = "sha256:" + strings.Repeat("b", 64)
			case "tampered-signature":
				envelope.Signature = base64.StdEncoding.EncodeToString(make([]byte, 64))
			}
			if _, err := authority.Authorize(context.Background(), envelope, challenge); err == nil {
				t.Fatal("signed denied state")
			}
			if signer.calls != before {
				t.Fatal("denied state reached signer")
			}
			source.x = saved
			source.err = nil
			envelope = savedEnvelope
		})
	}
}

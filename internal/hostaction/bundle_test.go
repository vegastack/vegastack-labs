package hostaction

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"strings"
	"testing"
	"time"
)

func TestEnvelopeRejectsUntrustedBytes(t *testing.T) {
	for _, raw := range [][]byte{nil, []byte(`{}`), []byte(`{"schema":"x","schema":"y"}`), bytes.Repeat([]byte("x"), 65537)} {
		if _, err := VerifyEnvelope(raw, Policy{}, time.Now()); err == nil {
			t.Fatalf("accepted untrusted envelope length %d", len(raw))
		}
	}
}

func fixtureBundle(t *testing.T) (generated.HostActionBundle, Policy, ed25519.PrivateKey, time.Time) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 9, 7, 0, 0, 0, time.UTC)
	digest := "sha256:" + strings.Repeat("a", 64)
	b := generated.HostActionBundle{Schema: generated.SchemaIDHostActionBundle, SchemaVersion: "1.0.0", ActionID: "test.write-file", ActionVersion: "1.0.0", ActionInput: "{}", ActionInputDigest: BytesDigest([]byte("{}")), BundleID: "bundle-a", PlanID: "plan-a", PlanDigest: digest, RunID: "run-a", StepID: "step-a", LeaseID: "lease-a", HostID: "host-a", HostIdentityDigest: digest, DeclarationID: "declaration-a", DeclarationRevision: 1, StateRevision: 2, RecoveryEpoch: 0, AutomationPrincipalID: "automation-a", CallerUID: 1001, CredentialReferenceID: "credential-a", CredentialMaterialVersion: "version-a", ConsoleConfirmationDigest: digest, IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339)}
	return b, Policy{HostID: b.HostID, HostIdentityDigest: digest, CallerUID: 1001, KeyID: "key-a", PublicKey: public}, private, now
}
func TestEnvelopeExactSignatureAndEveryField(t *testing.T) {
	b, p, key, now := fixtureBundle(t)
	raw, err := SignEnvelope(b, p.KeyID, key)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := VerifyEnvelope(raw, p, now); err != nil || got != b {
		t.Fatalf("valid envelope: %v", err)
	}
	var original map[string]any
	if err := json.Unmarshal(raw, &original); err != nil {
		t.Fatal(err)
	}
	fields := original["bundle"].(map[string]any)
	for name := range fields {
		t.Run(name, func(t *testing.T) {
			var mutated map[string]any
			_ = json.Unmarshal(raw, &mutated)
			values := mutated["bundle"].(map[string]any)
			switch value := values[name].(type) {
			case string:
				values[name] = value + "x"
			case float64:
				values[name] = value + 1
			default:
				t.Fatal("unhandled field")
			}
			candidate, _ := json.Marshal(mutated)
			if _, err := VerifyEnvelope(candidate, p, now); err == nil {
				t.Fatalf("accepted changed %s", name)
			}
		})
	}
	for _, at := range []time.Time{now.Add(-time.Second), now.Add(time.Minute)} {
		if _, err := VerifyEnvelope(raw, p, at); err == nil {
			t.Fatal("accepted invalid time")
		}
	}
	p.KeyID = "other"
	if _, err := VerifyEnvelope(raw, p, now); err == nil {
		t.Fatal("accepted unknown signer")
	}
}
func TestAuthorizationBindsFreshChallenge(t *testing.T) {
	b, p, key, now := fixtureBundle(t)
	digest, _ := BundleDigest(b)
	c := generated.HostActionChallenge{Schema: generated.SchemaIDHostActionChallenge, SchemaVersion: "1.0.0", BundleDigest: digest, Nonce: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), HostID: b.HostID, StartedAt: now.Format(time.RFC3339)}
	a := generated.HostActionAuthorization{Schema: generated.SchemaIDHostActionAuthorization, SchemaVersion: "1.0.0", BundleDigest: digest, ChallengeDigest: Digest(c), KeyID: p.KeyID, AuthorizedAt: now.Add(time.Second).Format(time.RFC3339), ExpiresAt: now.Add(5 * time.Second).Format(time.RFC3339), StateRevision: b.StateRevision, RecoveryEpoch: b.RecoveryEpoch}
	a.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, AuthorizationMessage(a)))
	raw, _ := json.Marshal(a)
	if err := VerifyAuthorization(raw, c, b, p, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	c.Nonce = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	if err := VerifyAuthorization(raw, c, b, p, now.Add(2*time.Second)); err == nil {
		t.Fatal("replayed challenge")
	}
}

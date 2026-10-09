// Package hostaction implements the non-resident, independently verified action boundary.
package hostaction

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/strictjson"
)

const MaximumEnvelope = 65536
const MaximumFrame = 8192

// MaximumResultFrame bounds only the final measured result; authentication stays 8 KiB.
const MaximumResultFrame = 262144
const AuthorizationWindow = 5 * time.Second
const envelopeDomain = "vsk-host-action-envelope-v1\x00"
const authorizationDomain = "vsk-host-action-authorization-v1\x00"

type Policy struct {
	HostID             string            `json:"hostId"`
	HostIdentityDigest string            `json:"hostIdentityDigest"`
	CallerUID          uint32            `json:"callerUid"`
	KeyID              string            `json:"keyId"`
	PublicKey          ed25519.PublicKey `json:"publicKey"`
	ReceiptDirectory   string            `json:"receiptDirectory"`
}
type Handler interface {
	Execute(context.Context, generated.HostActionBundle) (generated.HostActionResult, error)
	Verify(context.Context, generated.HostActionBundle, generated.HostActionResult) error
}
type Dispatcher interface {
	Lookup(string, string) (Handler, bool)
}

func blocked() error {
	return failure.New(generated.ErrorCodeAuthorizationDenied, "host-action", false)
}
func Digest(value any) string { raw, _ := json.Marshal(value); return BytesDigest(raw) }
func BytesDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func decode(raw []byte, schema string, max int, out any) error {
	if len(raw) == 0 || len(raw) > max || generated.ValidateContractJSON(schema, raw, generated.ContractExact) != nil || json.Unmarshal(raw, out) != nil {
		return blocked()
	}
	return nil
}
func BundleDigest(bundle generated.HostActionBundle) (string, error) {
	if bundle.ActionID == "debian.access.confirm" {
		if bundle.VerificationEvidence == nil || bundle.VerificationEvidenceDigest != Digest(bundle.VerificationEvidence) {
			return "", blocked()
		}
	} else if bundle.VerificationEvidence != nil || bundle.VerificationEvidenceDigest != "" {
		return "", blocked()
	}
	raw, err := json.Marshal(bundle)
	if err != nil || len(raw) > MaximumEnvelope || generated.ValidateContractJSON(generated.SchemaIDHostActionBundle, raw, generated.ContractExact) != nil || bundle.CallerUID > int64(^uint32(0)) || bundle.ActionInputDigest != BytesDigest([]byte(bundle.ActionInput)) || strictjson.Scan(context.Background(), []byte(bundle.ActionInput), strictjson.Limits{MaxDepth: 16}) != nil {
		return "", blocked()
	}
	return BytesDigest(raw), nil
}
func EnvelopeMessage(bundle generated.HostActionBundle, keyID string) ([]byte, error) {
	if _, err := BundleDigest(bundle); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(struct {
		KeyID  string                     `json:"keyId"`
		Bundle generated.HostActionBundle `json:"bundle"`
	}{keyID, bundle})
	if err != nil {
		return nil, blocked()
	}
	return append([]byte(envelopeDomain), raw...), nil
}
func SignEnvelope(bundle generated.HostActionBundle, keyID string, key ed25519.PrivateKey) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, blocked()
	}
	message, err := EnvelopeMessage(bundle, keyID)
	if err != nil {
		return nil, err
	}
	envelope := generated.HostActionEnvelope{Schema: generated.SchemaIDHostActionEnvelope, SchemaVersion: "1.0.0", Bundle: bundle, KeyID: keyID, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, message))}
	raw, err := json.Marshal(envelope)
	if err != nil || len(raw) > MaximumEnvelope || generated.ValidateContractJSON(generated.SchemaIDHostActionEnvelope, raw, generated.ContractExact) != nil {
		return nil, blocked()
	}
	return raw, nil
}
func VerifyEnvelope(raw []byte, policy Policy, now time.Time) (generated.HostActionBundle, error) {
	var e generated.HostActionEnvelope
	if decode(raw, generated.SchemaIDHostActionEnvelope, MaximumEnvelope, &e) != nil || len(policy.PublicKey) != ed25519.PublicKeySize || policy.CallerUID == 0 || policy.KeyID != e.KeyID || policy.HostID != e.Bundle.HostID || policy.HostIdentityDigest != e.Bundle.HostIdentityDigest || int64(policy.CallerUID) != e.Bundle.CallerUID {
		return generated.HostActionBundle{}, blocked()
	}
	message, err := EnvelopeMessage(e.Bundle, e.KeyID)
	signature, e2 := base64.StdEncoding.Strict().DecodeString(e.Signature)
	issued, e3 := time.Parse(time.RFC3339, e.Bundle.IssuedAt)
	expires, e4 := time.Parse(time.RFC3339, e.Bundle.ExpiresAt)
	if err != nil || e2 != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(policy.PublicKey, message, signature) || e3 != nil || e4 != nil || now.Before(issued) || !now.Before(expires) || !issued.Before(expires) || expires.Sub(issued) > 5*time.Minute {
		return generated.HostActionBundle{}, blocked()
	}
	return e.Bundle, nil
}
func AuthorizationMessage(value generated.HostActionAuthorization) []byte {
	value.Signature = ""
	raw, _ := json.Marshal(value)
	return append([]byte(authorizationDomain), raw...)
}
func VerifyAuthorization(raw []byte, c generated.HostActionChallenge, b generated.HostActionBundle, p Policy, now time.Time) error {
	var a generated.HostActionAuthorization
	if decode(raw, generated.SchemaIDHostActionAuthorization, MaximumFrame, &a) != nil || len(p.PublicKey) != ed25519.PublicKeySize {
		return blocked()
	}
	nonce, err := base64.StdEncoding.Strict().DecodeString(c.Nonce)
	digest, e2 := BundleDigest(b)
	started, e3 := time.Parse(time.RFC3339, c.StartedAt)
	at, e4 := time.Parse(time.RFC3339, a.AuthorizedAt)
	expiry, e5 := time.Parse(time.RFC3339, a.ExpiresAt)
	bundleExpiry, e6 := time.Parse(time.RFC3339, b.ExpiresAt)
	signature, e7 := base64.StdEncoding.Strict().DecodeString(a.Signature)
	if err != nil || len(nonce) != 32 || e2 != nil || e3 != nil || e4 != nil || e5 != nil || e6 != nil || e7 != nil || c.HostID != b.HostID || c.BundleDigest != digest || a.BundleDigest != digest || a.ChallengeDigest != Digest(c) || a.KeyID != p.KeyID || a.StateRevision != b.StateRevision || a.RecoveryEpoch != b.RecoveryEpoch || started.After(at) || now.Before(at) || !now.Before(expiry) || !at.Before(expiry) || expiry.Sub(at) > AuthorizationWindow || expiry.After(bundleExpiry) || now.Sub(started) > AuthorizationWindow || !ed25519.Verify(p.PublicKey, AuthorizationMessage(a), signature) {
		return blocked()
	}
	return nil
}

// ExecutionDigest consumes the approved operation, not a transient signature or lease.
// A new run/lease or refreshed signature cannot authorize the same plan twice.
func ExecutionDigest(b generated.HostActionBundle) string {
	return Digest([]string{"host-action-consumption-v1", b.PlanID, b.PlanDigest, b.HostID, b.ActionID, b.ActionVersion, b.ActionInputDigest})
}

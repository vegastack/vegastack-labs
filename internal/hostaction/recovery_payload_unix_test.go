//go:build linux || darwin

package hostaction

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"os"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

type recoveryWireHandler struct{ calls, promoted int }

func (h *recoveryWireHandler) Execute(context.Context, generated.HostActionBundle) (generated.HostActionResult, error) {
	return generated.HostActionResult{}, blocked()
}
func (h *recoveryWireHandler) Verify(context.Context, generated.HostActionBundle, generated.HostActionResult) error {
	return nil
}
func (h *recoveryWireHandler) ExecuteRecoveryPayload(ctx context.Context, b generated.HostActionBundle, r io.Reader) (generated.HostActionResult, error) {
	h.calls++
	if CopyRecoveryPayload(ctx, io.Discard, r, 3, MaximumRecoveryCandidateBytes, BytesDigest([]byte{0, 1, 2})) != nil || CopyRecoveryPayload(ctx, io.Discard, r, 2, MaximumRecoveryJournalBytes, BytesDigest([]byte{3, 4})) != nil {
		return generated.HostActionResult{}, blocked()
	}
	var one [1]byte
	if n, e := r.Read(one[:]); n != 0 || e != io.EOF {
		return generated.HostActionResult{}, blocked()
	}
	h.promoted++
	digest, _ := BundleDigest(b)
	return generated.HostActionResult{Schema: generated.SchemaIDHostActionResult, SchemaVersion: "1.0.0", BundleDigest: digest, ResultDigest: BytesDigest([]byte("result")), Status: "succeeded", Changed: true, EffectObserved: true, Reason: "verified"}, nil
}

type recoveryWireDispatcher struct{ handler Handler }

func (d recoveryWireDispatcher) Lookup(string, string) (Handler, bool) { return d.handler, true }
func TestRecoveryPayloadAuthorizationClaimAndTrailingBoundary(t *testing.T) {
	for _, variant := range []string{"valid", "bad-authorization", "ordinary-action", "truncated", "wrong-hash", "trailing", "replay"} {
		t.Run(variant, func(t *testing.T) {
			b, p, key, now := fixtureBundle(t)
			b.ActionID = RecoveryReceiveAction
			if variant == "ordinary-action" {
				b.ActionID = "test.write-file"
			}
			root := t.TempDir()
			if os.Chmod(root, 0700) != nil {
				t.Fatal("mode")
			}
			receipts, err := OpenReceipts(root, uint32(os.Geteuid()))
			if err != nil {
				t.Fatal(err)
			}
			defer receipts.Close()
			nonce := bytes.Repeat([]byte{7}, 32)
			digest, _ := BundleDigest(b)
			challenge := generated.HostActionChallenge{Schema: generated.SchemaIDHostActionChallenge, SchemaVersion: "1.0.0", BundleDigest: digest, Nonce: base64.StdEncoding.EncodeToString(nonce), HostID: b.HostID, StartedAt: now.Format(time.RFC3339)}
			auth := generated.HostActionAuthorization{Schema: generated.SchemaIDHostActionAuthorization, SchemaVersion: "1.0.0", BundleDigest: digest, ChallengeDigest: Digest(challenge), KeyID: p.KeyID, AuthorizedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(5 * time.Second).Format(time.RFC3339), StateRevision: b.StateRevision, RecoveryEpoch: b.RecoveryEpoch}
			auth.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, AuthorizationMessage(auth)))
			if variant == "bad-authorization" {
				auth.Signature = base64.StdEncoding.EncodeToString(make([]byte, 64))
			}
			raw, err := SignEnvelope(b, p.KeyID, key)
			if err != nil {
				t.Fatal(err)
			}
			var wire bytes.Buffer
			wire.Write(raw)
			wire.WriteByte('\n')
			if WriteFrame(&wire, auth, MaximumFrame) != nil {
				t.Fatal("auth")
			}
			payload := []byte{0, 1, 2, 3, 4}
			if variant == "truncated" {
				payload = payload[:4]
			}
			if variant == "wrong-hash" {
				payload[0] = 9
			}
			if variant == "trailing" {
				payload = append(payload, 5)
			}
			wire.Write(payload)
			handler := &recoveryWireHandler{}
			if variant == "replay" {
				if receipts.ClaimExecution(ExecutionDigest(b), digest) != nil {
					t.Fatal("claim")
				}
			}
			var output bytes.Buffer
			err = RunOnce(context.Background(), bytes.NewReader(wire.Bytes()), &output, p, receipts, recoveryWireDispatcher{handler}, func() time.Time { return now }, bytes.NewReader(nonce))
			if variant == "valid" {
				if err != nil || handler.promoted != 1 {
					t.Fatalf("valid: %v promoted=%d", err, handler.promoted)
				}
			} else if err == nil || handler.promoted != 0 {
				t.Fatal("invalid input promoted")
			}
			if (variant == "bad-authorization" || variant == "ordinary-action" || variant == "replay") && handler.calls != 0 {
				t.Fatal("payload handler entered before authority")
			}
		})
	}
}

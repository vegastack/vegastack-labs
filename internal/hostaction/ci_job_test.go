//go:build linux || darwin

package hostaction

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"io"
	"os"
	"testing"
	"time"
)

type ciWireHandler struct{ calls int }

func (h *ciWireHandler) Execute(context.Context, generated.HostActionBundle) (generated.HostActionResult, error) {
	return generated.HostActionResult{}, blocked()
}
func (h *ciWireHandler) Verify(_ context.Context, _ generated.HostActionBundle, r generated.HostActionResult) error {
	return ValidateResult(r)
}
func (h *ciWireHandler) ExecuteCI(_ context.Context, b generated.HostActionBundle, input io.ReadCloser, output io.Writer) (generated.HostActionResult, error) {
	h.calls++
	var payload [7]byte
	if _, e := io.ReadFull(input, payload[:]); e != nil || string(payload[:]) != "private" {
		return generated.HostActionResult{}, blocked()
	}
	d, _ := BundleDigest(b)
	r := generated.HostActionResult{Schema: generated.SchemaIDHostActionResult, SchemaVersion: "1.0.0", BundleDigest: d, Status: "succeeded", Changed: true, EffectObserved: true, Reason: "verified"}
	r.ResultDigest = ResultDigest(r)
	return r, nil
}
func TestCIDuplexRequiresAuthorizationAndKeepsBufferedBytes(t *testing.T) {
	for _, variant := range []string{"valid", "bad-authorization", "ordinary-action", "replay"} {
		t.Run(variant, func(t *testing.T) {
			b, p, key, now := fixtureBundle(t)
			b.ActionID = CIJobAction
			if variant == "ordinary-action" {
				b.ActionID = "test.write-file"
			}
			root := t.TempDir()
			if os.Chmod(root, 0700) != nil {
				t.Fatal("mode")
			}
			receipts, e := OpenReceipts(root, uint32(os.Geteuid()))
			if e != nil {
				t.Fatal(e)
			}
			defer receipts.Close()
			nonce := bytes.Repeat([]byte{7}, 32)
			d, _ := BundleDigest(b)
			challenge := generated.HostActionChallenge{Schema: generated.SchemaIDHostActionChallenge, SchemaVersion: "1.0.0", BundleDigest: d, Nonce: base64.StdEncoding.EncodeToString(nonce), HostID: b.HostID, StartedAt: now.Format(time.RFC3339)}
			auth := generated.HostActionAuthorization{Schema: generated.SchemaIDHostActionAuthorization, SchemaVersion: "1.0.0", BundleDigest: d, ChallengeDigest: Digest(challenge), KeyID: p.KeyID, AuthorizedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(5 * time.Second).Format(time.RFC3339), StateRevision: b.StateRevision, RecoveryEpoch: b.RecoveryEpoch}
			auth.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, AuthorizationMessage(auth)))
			if variant == "bad-authorization" {
				auth.Signature = base64.StdEncoding.EncodeToString(make([]byte, 64))
			}
			env, e := SignEnvelope(b, p.KeyID, key)
			if e != nil {
				t.Fatal(e)
			}
			var wire bytes.Buffer
			wire.Write(env)
			wire.WriteByte('\n')
			if WriteFrame(&wire, auth, MaximumFrame) != nil {
				t.Fatal("auth")
			}
			wire.WriteString("private")
			if variant == "replay" && receipts.ClaimExecution(ExecutionDigest(b), d) != nil {
				t.Fatal("claim")
			}
			h := &ciWireHandler{}
			var output bytes.Buffer
			e = RunOnce(context.Background(), io.NopCloser(bytes.NewReader(wire.Bytes())), &output, p, receipts, recoveryWireDispatcher{h}, func() time.Time { return now }, bytes.NewReader(nonce))
			if variant == "valid" {
				if e != nil || h.calls != 1 {
					t.Fatal(e, h.calls)
				}
			} else if e == nil || h.calls != 0 {
				t.Fatal("invalid stream executed", e, h.calls)
			}
		})
	}
}

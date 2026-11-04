//go:build linux || darwin

package hostaction

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSignedProtocolAllowsBoundedSubsecondClockSkew(t *testing.T) {
	for _, tc := range []struct {
		name        string
		phase, skew time.Duration
		deny        bool
	}{
		{"zero", 100 * time.Millisecond, 0, false},
		{"host-too-far-behind", 100 * time.Millisecond, -2250 * time.Millisecond, true},
		{"host-too-far-ahead", 900 * time.Millisecond, 2250 * time.Millisecond, true},
		{"host-behind-250ms-cross-second", 100 * time.Millisecond, -250 * time.Millisecond, false},
		{"host-ahead-250ms-cross-second", 900 * time.Millisecond, 250 * time.Millisecond, false},
		{"host-behind-250ms-within-second", 900 * time.Millisecond, -250 * time.Millisecond, false},
		{"host-ahead-250ms-within-second", 100 * time.Millisecond, 250 * time.Millisecond, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, p, key, base := fixtureBundle(t)
			controller := base.Add(2*time.Second + tc.phase)
			host := controller.Add(tc.skew)
			b.ExpiresAt = base.Add(time.Minute).Format(time.RFC3339)
			raw, e := SignEnvelope(b, p.KeyID, key)
			if e != nil {
				t.Fatal(e)
			}
			var env generated.HostActionEnvelope
			json.Unmarshal(raw, &env)
			bd, _ := BundleDigest(b)
			nonce := bytes.Repeat([]byte{7}, 32)
			c := generated.HostActionChallenge{Schema: generated.SchemaIDHostActionChallenge, SchemaVersion: "1.0.0", BundleDigest: bd, Nonce: base64.StdEncoding.EncodeToString(nonce), HostID: b.HostID, StartedAt: host.UTC().Truncate(time.Second).Format(time.RFC3339)}
			at := controller.UTC().Truncate(time.Second)
			a := generated.HostActionAuthorization{Schema: generated.SchemaIDHostActionAuthorization, SchemaVersion: "1.0.0", BundleDigest: bd, ChallengeDigest: Digest(c), KeyID: p.KeyID, AuthorizedAt: at.Format(time.RFC3339), ExpiresAt: at.Add(5 * time.Second).Format(time.RFC3339), StateRevision: b.StateRevision, RecoveryEpoch: b.RecoveryEpoch}
			a.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, AuthorizationMessage(a)))
			var in, out bytes.Buffer
			WriteFrame(&in, env, MaximumEnvelope)
			WriteFrame(&in, a, MaximumFrame)
			root := t.TempDir()
			os.Chmod(root, 0700)
			r, e := OpenReceipts(root, uint32(os.Geteuid()))
			if e != nil {
				t.Fatal(e)
			}
			defer r.Close()
			e = RunOnce(context.Background(), &in, &out, p, r, testDispatcher{fileHandler{filepath.Join(root, "effect")}}, func() time.Time { return host }, bytes.NewReader(nonce))
			_, effectErr := os.Stat(filepath.Join(root, "effect"))
			_, claimErr := os.Stat(filepath.Join(root, ExecutionDigest(b)[7:]+".json"))
			t.Logf("offset=%s controller=%s host=%s challenge=%s authorization=%s rejected=%v effect=%v claim=%v", tc.skew, controller.Format(time.RFC3339Nano), host.Format(time.RFC3339Nano), c.StartedAt, a.AuthorizedAt, e != nil, effectErr == nil, claimErr == nil)
			if (e != nil) != tc.deny {
				t.Fatalf("unexpected result %v; wire %s", e, out.String())
			}
			if tc.deny && (effectErr == nil || claimErr == nil) {
				t.Fatal("claim/effect despite rejection")
			}
			if !tc.deny && (effectErr != nil || claimErr != nil) {
				t.Fatal("successful handshake did not persist claim and effect")
			}
		})
	}
}

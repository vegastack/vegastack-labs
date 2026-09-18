package audit

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
)

type testCheckpointSigner struct{ private ed25519.PrivateKey }

func (signer testCheckpointSigner) Sign(_ context.Context, digest Fingerprint, _ credentialref.Reference) (Signature, error) {
	bytes := ed25519.Sign(signer.private, []byte(digest))
	return Signature{PublicKeyID: "key-a", Bytes: bytes, Digest: SignatureDigest(bytes)}, nil
}

func (testCheckpointSigner) Verify(digest Fingerprint, signature Signature, key PublicKey) error {
	if key.ID != signature.PublicKeyID || !ed25519.Verify(ed25519.PublicKey(key.Bytes), []byte(digest), signature.Bytes) {
		return errors.New("bad signature")
	}
	return nil
}

func TestCheckpointDigestAndSignatureBindExactRange(t *testing.T) {
	event := chainEventFixture(t)
	link, err := MakeChainLink(event, ContextIDs{}, "instance-a", 1, testGenesisDigest(), false)
	if err != nil {
		t.Fatal(err)
	}
	rangeDigest, err := DigestChainRange([]ChainLink{link})
	if err != nil {
		t.Fatal(err)
	}
	chain := ChainRange{FirstEventID: event.EventID, LastEventID: event.EventID, Links: []ChainLink{link}, RangeDigest: rangeDigest}
	reference := credentialref.Reference{ID: "signer-a", Consumer: "core.audit.signer"}
	digest, err := CheckpointDigest(chain, "instance-a", event.RecoveryEpoch, reference, "version-a", "audit-anchor")
	if err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := testCheckpointSigner{private: private}
	signature, err := signer.Sign(context.Background(), digest, reference)
	if err != nil {
		t.Fatal(err)
	}
	if err := signer.Verify(digest, signature, PublicKey{ID: "key-a", Bytes: private.Public().(ed25519.PublicKey)}); err != nil {
		t.Fatal(err)
	}
	changed := chain
	changed.LastEventID++
	if changedDigest, err := CheckpointDigest(changed, "instance-a", event.RecoveryEpoch, reference, "version-a", "audit-anchor"); err != nil || changedDigest == digest {
		t.Fatal("checkpoint range binding lost")
	}
}

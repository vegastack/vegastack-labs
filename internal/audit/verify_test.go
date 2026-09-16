package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestVerifyLocalDetectsPayloadEditAndFork(t *testing.T) {
	first := chainEventFixture(t)
	one, err := MakeChainLink(first, ContextIDs{}, "instance-a", 1, testGenesisDigest(), false)
	if err != nil {
		t.Fatal(err)
	}
	second := first
	second.EventID++
	second.CorrelationID = "correlation-b"
	two, err := MakeChainLink(second, ContextIDs{}, "instance-a", 2, one.LinkDigest, false)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := VerifyLocal([]ChainLink{one, two}, []Event{first, second}, nil); err != nil || result.Status != "degraded" {
		t.Fatal(err)
	}
	changed := second
	changed.Target.ID = "changed-target"
	if result, err := VerifyLocal([]ChainLink{one, two}, []Event{first, changed}, nil); err == nil || result.Status != "incident" {
		t.Fatal("payload edit accepted")
	}
	forked := two
	forked.PreviousDigest = testOtherDigest()
	if result, err := VerifyLocal([]ChainLink{one, forked}, []Event{first, second}, nil); err == nil || result.Status != "incident" {
		t.Fatal("fork accepted")
	}
}

func TestAheadIndependentCheckpointForcesIncident(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := Fingerprint("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	signatureDigest := Fingerprint("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	receipt := "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	independent := "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	cp := generated.AuditCheckpoint{CheckpointID: "checkpoint-a", FirstEventID: 1, LastEventID: 1, FirstSegmentSequence: 1, LastSegmentSequence: 1, ChainDigest: string(digest), InstanceID: "instance-a", RecoveryEpoch: 1, SignerReferenceID: "signer-a", SignerMaterialVersion: "version-a", SignatureDigest: &[]string{string(signatureDigest)}[0], ExportReceiptDigest: &receipt, IndependentReadDigest: &independent, Status: "anchored"}
	local := LocalResult{Status: "anchored", InstanceID: "instance-a", RecoveryEpoch: 1, LastAnchored: &cp, LocalDigest: digest, LastSequence: 1, Namespace: "audit-anchor"}
	reference := credentialref.Reference{ID: "signer-a", Consumer: "core.audit.signer"}
	signed, err := CheckpointBindingDigest(1, 1, 1, 1, digest, "instance-a", 1, reference, "version-a", "audit-anchor")
	if err != nil {
		t.Fatal(err)
	}
	bytes := ed25519.Sign(private, []byte(signed))
	remote := IndependentCheckpoint{CheckpointID: "checkpoint-a", InstanceID: "instance-a", RecoveryEpoch: 1, LastEventID: 2, LastSequence: 2, ChainDigest: digest, SignerReference: reference, MaterialVersion: "version-a", Namespace: "audit-anchor", SignedDigest: signed, Signature: Signature{PublicKeyID: "key-a", Bytes: bytes, Digest: SignatureDigest(bytes)}, ExportReceipt: Fingerprint(receipt), IndependentRead: Fingerprint(independent)}
	result, err := CompareIndependent(local, remote, PublicKey{ID: "key-a", Bytes: public})
	if err == nil || result.Status != "incident" || result.ReasonCode != "independent-checkpoint-ahead" {
		t.Fatal("ahead anchor accepted")
	}
}

//go:build linux || darwin

package recovery

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSignedProtectedManifestEstablishesPin(t *testing.T) {
	adminPublic, adminPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	witnessPublic, witnessPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, binding, _, now := witnessFixture(t)
	payload := RecoveryManifest{ManifestID: "manifest-1", WitnessKeyID: "witness-key-1", WitnessInstanceID: "outside-instance", WitnessPublicKey: witnessPublic, RecipientKeyID: "recipient-1", RecipientPublicKey: recipient.PublicKey().Bytes(), Binding: binding, ValidFrom: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}
	canonical, err := CanonicalRecoveryManifest(payload)
	if err != nil {
		t.Fatal(err)
	}
	artifact := SignedRecoveryManifest{Payload: payload, Signature: ed25519.Sign(adminPrivate, canonical)}
	raw, err := json.Marshal(artifact)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := ParseSignedRecoveryManifest(raw, adminPublic, binding, now)
	if err != nil {
		t.Fatal(err)
	}
	if !pin.AuthenticatedExternally || pin.KeyID != payload.WitnessKeyID || pin.RecipientKeyID != payload.RecipientKeyID {
		t.Fatal("independent pin missing")
	}
	witnessPayload := WitnessPayload{Binding: binding, KeyID: pin.KeyID, WitnessInstanceID: pin.WitnessInstanceID, IssuedAt: now.Add(-time.Second), ObservedAt: now.Add(-time.Second), ExpiresAt: now.Add(30 * time.Second)}
	witnessCanonical, err := CanonicalWitnessPayload(witnessPayload)
	if err != nil {
		t.Fatal(err)
	}
	signed := SignedWitness{Payload: witnessPayload, Signature: ed25519.Sign(witnessPrivate, witnessCanonical)}
	if err := VerifySignedWitness(context.Background(), pin, binding, signed, now); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*SignedRecoveryManifest){
		"changed-recipient": func(a *SignedRecoveryManifest) { a.Payload.RecipientKeyID = "other" },
		"wrong-host":        func(a *SignedRecoveryManifest) { a.Payload.Binding.ReplacementHostID = "other" },
		"wrong-draft":       func(a *SignedRecoveryManifest) { a.Payload.Binding.DraftID = "other" },
		"wrong-challenge":   func(a *SignedRecoveryManifest) { a.Payload.Binding.ChallengeID = "other" },
		"old-witness":       func(a *SignedRecoveryManifest) { a.Payload.WitnessInstanceID = binding.FormerInstanceID },
		"revoked":           func(a *SignedRecoveryManifest) { a.Payload.Revoked = true },
	} {
		t.Run(name, func(t *testing.T) {
			copy := artifact
			mutate(&copy)
			if name != "changed-recipient" && name != "revoked" {
				changedCanonical, err := CanonicalRecoveryManifest(copy.Payload)
				if err != nil {
					t.Fatal(err)
				}
				copy.Signature = ed25519.Sign(adminPrivate, changedCanonical)
			}
			data, _ := json.Marshal(copy)
			if _, err := ParseSignedRecoveryManifest(data, adminPublic, binding, now); err == nil {
				t.Fatal("invalid manifest accepted")
			}
		})
	}
	pin.PublicKey = append(ed25519.PublicKey(nil), witnessPublic...)
	pin.PublicKey[0] ^= 1
	if err := VerifySignedWitness(context.Background(), pin, binding, signed, now); err == nil {
		t.Fatal("mutable pin escaped manifest seal")
	}
}

func TestProtectedManifestFileRejectsWeakPath(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "manifest")
	if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readProtectedWitnessFile(path, uint32(os.Geteuid()), 1024); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := readProtectedWitnessFile(path, uint32(os.Geteuid()), 1024); err == nil {
		t.Fatal("weak mode accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readProtectedWitnessFile(link, uint32(os.Geteuid()), 1024); err == nil {
		t.Fatal("symlink accepted")
	}
	hardlink := filepath.Join(dir, "hardlink")
	if err := os.Link(path, hardlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readProtectedWitnessFile(path, uint32(os.Geteuid()), 1024); err == nil {
		t.Fatal("hardlink accepted")
	}
}

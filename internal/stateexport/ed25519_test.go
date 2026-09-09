package stateexport

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"
)

const syntheticKeyID = "synthetic-test-only-ed25519-1"

type fixedEd25519Signer struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

type fixedEd25519Verifier struct {
	publicKey ed25519.PublicKey
}

func fixedTestSigner(t *testing.T) Signer {
	t.Helper()
	seed := [ed25519.SeedSize]byte{1, 3, 3, 7, 2, 9, 1, 1, 4, 2, 0, 2, 6, 9, 0, 8, 3, 7, 3, 7, 1, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := append(ed25519.PublicKey(nil), privateKey.Public().(ed25519.PublicKey)...)
	return &fixedEd25519Signer{privateKey: privateKey, publicKey: publicKey}
}

func fixedTestVerifier(t *testing.T) Verifier {
	t.Helper()
	signer := fixedTestSigner(t).(*fixedEd25519Signer)
	return &fixedEd25519Verifier{publicKey: append(ed25519.PublicKey(nil), signer.publicKey...)}
}

func wrongTestVerifier(t *testing.T) Verifier {
	t.Helper()
	seed := [ed25519.SeedSize]byte{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9}
	key := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
	return &fixedEd25519Verifier{publicKey: key}
}

func (signer *fixedEd25519Signer) Sign(ctx context.Context, request SignRequest) (DetachedSignature, error) {
	if ctx.Err() != nil {
		return DetachedSignature{}, errors.New("interrupted")
	}
	input, err := SigningInput(request)
	if err != nil {
		return DetachedSignature{}, err
	}
	spki, err := x509.MarshalPKIXPublicKey(signer.publicKey)
	if err != nil {
		return DetachedSignature{}, err
	}
	fingerprint := sha256.Sum256(spki)
	return DetachedSignature{
		Algorithm: SignatureAlgorithm, KeyID: syntheticKeyID,
		KeyFingerprint: "sha256:" + hex.EncodeToString(fingerprint[:]),
		Value:          base64.RawURLEncoding.EncodeToString(ed25519.Sign(signer.privateKey, input)),
	}, nil
}

func (verifier *fixedEd25519Verifier) Verify(ctx context.Context, request SignRequest, signature DetachedSignature) error {
	if ctx.Err() != nil {
		return errors.New("interrupted")
	}
	input, err := SigningInput(request)
	if err != nil {
		return err
	}
	spki, err := x509.MarshalPKIXPublicKey(verifier.publicKey)
	if err != nil {
		return err
	}
	fingerprint := sha256.Sum256(spki)
	if signature.KeyID != syntheticKeyID || signature.KeyFingerprint != "sha256:"+hex.EncodeToString(fingerprint[:]) {
		return errors.New("unexpected synthetic trust identity")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(signature.Value)
	if err != nil || !ed25519.Verify(verifier.publicKey, input, decoded) {
		return errors.New("signature invalid")
	}
	return nil
}

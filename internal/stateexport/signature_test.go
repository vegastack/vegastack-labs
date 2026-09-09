package stateexport

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

func signedFixture(t *testing.T) SignedExport {
	t.Helper()
	payload := publicPayloadFixture(t)
	_, digest, err := CanonicalPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := fixedTestSigner(t).Sign(context.Background(), SignRequest{Purpose: SigningPurpose, Digest: digest})
	if err != nil {
		t.Fatal(err)
	}
	return SignedExport{
		Schema: SignedExportSchema, SchemaVersion: SchemaVersion, Payload: payload,
		ContentDigest: digestString(digest), Signature: signature, VerificationStatus: VerificationVerified,
	}
}

func TestFixedEd25519FixtureSignsDeterministicallyAndVerifierIsIndependent(t *testing.T) {
	payload := publicPayloadFixture(t)
	_, digest, err := CanonicalPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	request := SignRequest{Purpose: SigningPurpose, Digest: digest}
	first, err := fixedTestSigner(t).Sign(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := fixedTestSigner(t).Sign(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || first.Algorithm != SignatureAlgorithm || !strings.HasPrefix(first.KeyID, "synthetic-test-only") {
		t.Fatalf("signatures = %#v / %#v", first, second)
	}
	if err := fixedTestVerifier(t).Verify(context.Background(), request, first); err != nil {
		t.Fatal(err)
	}
	if err := wrongTestVerifier(t).Verify(context.Background(), request, first); err == nil {
		t.Fatal("wrong verifier accepted signature")
	}
	want := SigningPurpose + "\nsha256:" + strings.Repeat("00", 32) + "\n"
	got, err := SigningInput(SignRequest{Purpose: SigningPurpose})
	if err != nil || string(got) != want {
		t.Fatalf("signing input = %q, %v", got, err)
	}
}

func TestVerifySignedExportRejectsEveryBindingTamper(t *testing.T) {
	valid := signedFixture(t)
	if err := VerifySignedExport(context.Background(), fixedTestVerifier(t), valid); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*SignedExport){
		"payload":     func(value *SignedExport) { value.Payload.StateRevision++ },
		"digest":      func(value *SignedExport) { value.ContentDigest = "sha256:" + strings.Repeat("0", 64) },
		"algorithm":   func(value *SignedExport) { value.Signature.Algorithm = "other" },
		"key id":      func(value *SignedExport) { value.Signature.KeyID = "other" },
		"fingerprint": func(value *SignedExport) { value.Signature.KeyFingerprint = "sha256:" + strings.Repeat("0", 64) },
		"signature": func(value *SignedExport) {
			raw, _ := base64.RawURLEncoding.DecodeString(value.Signature.Value)
			raw[0] ^= 1
			value.Signature.Value = base64.RawURLEncoding.EncodeToString(raw)
		},
		"schema":   func(value *SignedExport) { value.Schema = "wrong" },
		"version":  func(value *SignedExport) { value.SchemaVersion = "2.0.0" },
		"revision": func(value *SignedExport) { value.Payload.Draft.Ref.Revision = 0 },
		"status":   func(value *SignedExport) { value.VerificationStatus = "pending" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if err := VerifySignedExport(context.Background(), fixedTestVerifier(t), candidate); err == nil {
				t.Fatal("tamper verified")
			}
		})
	}
	if err := VerifySignedExport(context.Background(), nil, valid); err == nil {
		t.Fatal("nil verifier accepted")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := VerifySignedExport(cancelled, fixedTestVerifier(t), valid); err == nil {
		t.Fatal("cancelled verification succeeded")
	}
}

func TestSignedGoldenMatchesFixedFixture(t *testing.T) {
	want, err := os.ReadFile("testdata/signed-export-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	want = bytes.TrimSuffix(want, []byte("\n"))
	got, _, err := CanonicalSignedExport(signedFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("signed golden differs\n%s", got)
	}
}

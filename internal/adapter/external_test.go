package adapter

import (
	"strings"
	"testing"
)

func TestValidateReceiptObservationTreatsExternalResultAsUntrusted(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	for _, observation := range []ReceiptObservation{
		{Status: "running", ResultDigest: digest},
		{Status: "succeeded", ResultDigest: digest},
		{Status: "failed", ResultDigest: digest},
		{Status: "partial", ResultDigest: digest},
	} {
		if err := ValidateReceiptObservation(observation); err != nil {
			t.Fatalf("valid observation %#v: %v", observation, err)
		}
	}
	if err := ValidateReceiptObservation(ReceiptObservation{Status: "succeeded", ResultDigest: "plaintext"}); err == nil {
		t.Fatal("non-digest receipt result accepted")
	}
	if err := ValidateReceiptVerification(ReceiptVerification{Verified: true, Digest: digest, Changed: true}); err != nil {
		t.Fatal(err)
	}
}

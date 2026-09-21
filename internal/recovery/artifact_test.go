package recovery

import (
	"bytes"
	"testing"
)

func TestSignedWitnessArtifactRequiresExactCanonicalBytes(t *testing.T) {
	_, _, signed, _ := witnessFixture(t)
	encoded, err := EncodeSignedWitness(signed)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeSignedWitness(encoded)
	if err != nil || decoded.Payload.Binding != signed.Payload.Binding {
		t.Fatal("canonical witness artifact did not decode")
	}
	for name, raw := range map[string][]byte{
		"leading-whitespace": append([]byte(" "), encoded...),
		"trailing-json":      append(append([]byte(nil), encoded...), []byte("{}")...),
		"unknown-field":      bytes.Replace(encoded, []byte(`"signature"`), []byte(`"unknown":true,"signature"`), 1),
		"duplicate-field":    bytes.Replace(encoded, []byte(`"signature"`), []byte(`"signature":"AA==","signature"`), 1),
		"oversize":           bytes.Repeat([]byte("a"), 262145),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeSignedWitness(raw); err == nil {
				t.Fatal("noncanonical artifact accepted")
			}
		})
	}
}

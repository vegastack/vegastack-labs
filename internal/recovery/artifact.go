package recovery

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
)

const maxSignedWitnessArtifactBytes = 262144

// EncodeSignedWitness is the finite operator-carried public artifact. It
// carries only signed bindings and denial response digests, never custody
// material or a private key. Signature and independent probes are verified
// separately by VerifyWitnessBundle after decoding.
func EncodeSignedWitness(signed SignedWitness) ([]byte, error) {
	if len(signed.Signature) != ed25519.SignatureSize {
		return nil, ErrWitnessUnavailable
	}
	if _, err := CanonicalWitnessPayload(signed.Payload); err != nil {
		return nil, ErrWitnessUnavailable
	}
	payload := signed.Payload
	payload.IssuedAt = payload.IssuedAt.UTC()
	payload.ObservedAt = payload.ObservedAt.UTC()
	payload.ExpiresAt = payload.ExpiresAt.UTC()
	if payload.Transcripts != nil {
		payload.Transcripts = append([]DirectDenialTranscript(nil), payload.Transcripts...)
		for i := range payload.Transcripts {
			payload.Transcripts[i].ObservedAt = payload.Transcripts[i].ObservedAt.UTC()
			payload.Transcripts[i].ExpiresAt = payload.Transcripts[i].ExpiresAt.UTC()
			payload.Transcripts[i].SessionExpiry = payload.Transcripts[i].SessionExpiry.UTC()
		}
	}
	data, err := json.Marshal(SignedWitness{Payload: payload, Signature: signed.Signature})
	if err != nil || len(data) > maxSignedWitnessArtifactBytes {
		return nil, ErrWitnessUnavailable
	}
	return data, nil
}

func DecodeSignedWitness(raw []byte) (SignedWitness, error) {
	var zero SignedWitness
	if len(raw) == 0 || len(raw) > maxSignedWitnessArtifactBytes {
		return zero, ErrWitnessUnavailable
	}
	var signed SignedWitness
	if json.Unmarshal(raw, &signed) != nil {
		return zero, ErrWitnessUnavailable
	}
	canonical, err := EncodeSignedWitness(signed)
	if err != nil || !bytes.Equal(canonical, raw) {
		return zero, ErrWitnessUnavailable
	}
	return signed, nil
}

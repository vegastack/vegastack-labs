package recovery

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"
)

const qualificationDomain = "vegastack-labs.dev/recovery-adapter-qualification/v1\x00"
const maxQualificationArtifactBytes = 65536

// AdapterQualification is a bounded, administrator-signed registration for
// one exact direct-denial boundary. It never replaces a live endpoint probe.
type AdapterQualification struct {
	AdapterID            string    `json:"adapterId"`
	Kind                 string    `json:"kind"`
	SubjectID            string    `json:"subjectId"`
	TargetID             string    `json:"targetId"`
	FormerIdentityID     string    `json:"formerIdentityId"`
	ImplementationDigest string    `json:"implementationDigest"`
	ValidFrom            time.Time `json:"validFrom"`
	ExpiresAt            time.Time `json:"expiresAt"`
}

type QualificationRecord struct {
	RecordID string                 `json:"recordId"`
	Entries  []AdapterQualification `json:"entries"`
}

type SignedQualificationRecord struct {
	Payload   QualificationRecord `json:"payload"`
	Signature []byte              `json:"signature"`
}

func qualificationKey(entry AdapterQualification) string {
	return entry.Kind + "\x00" + entry.SubjectID + "\x00" + entry.TargetID + "\x00" + entry.FormerIdentityID + "\x00" + entry.AdapterID
}

func requirementQualificationKey(required BoundaryRequirement) string {
	return required.Kind + "\x00" + required.SubjectID + "\x00" + required.TargetID + "\x00" + required.FormerIdentityID + "\x00" + required.AdapterID
}

// CanonicalQualificationRecord signs a closed sorted registration list, not a
// caller-selected factory or a self-attested denial bit.
func CanonicalQualificationRecord(payload QualificationRecord) ([]byte, error) {
	if !validWitnessToken(payload.RecordID) || len(payload.Entries) == 0 || len(payload.Entries) > 256 {
		return nil, ErrWitnessUnavailable
	}
	keys := make([]string, len(payload.Entries))
	for i, entry := range payload.Entries {
		for _, token := range []string{entry.AdapterID, entry.Kind, entry.SubjectID, entry.TargetID, entry.FormerIdentityID} {
			if !validWitnessToken(token) {
				return nil, ErrWitnessUnavailable
			}
		}
		if !witnessDigest.MatchString(entry.ImplementationDigest) || entry.ValidFrom.IsZero() || entry.ExpiresAt.IsZero() || !entry.ValidFrom.Before(entry.ExpiresAt) || entry.ExpiresAt.Sub(entry.ValidFrom) > 24*time.Hour {
			return nil, ErrWitnessUnavailable
		}
		keys[i] = qualificationKey(entry)
		payload.Entries[i].ValidFrom = entry.ValidFrom.UTC()
		payload.Entries[i].ExpiresAt = entry.ExpiresAt.UTC()
	}
	if !sort.StringsAreSorted(keys) {
		return nil, ErrWitnessUnavailable
	}
	for i := 1; i < len(keys); i++ {
		if keys[i] == keys[i-1] {
			return nil, ErrWitnessUnavailable
		}
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, ErrWitnessUnavailable
	}
	return append([]byte(qualificationDomain), data...), nil
}

type qualifiedFactory struct {
	implementationDigest string
	new                  func(AdapterQualification) DirectDenialVerifier
}

// No real endpoint verifier has qualified for production. This is a compile-
// time closed map; test-only disposable factories never enter it.
var productionDenialFactories = map[string]qualifiedFactory{}

type qualifiedGroupVerifier struct {
	groups map[string]DirectDenialVerifier
}

func (verifier qualifiedGroupVerifier) VerifyDirectDenial(ctx context.Context, transcript DirectDenialTranscript) error {
	group := verifier.groups[requirementQualificationKey(transcript.Requirement)]
	if ctx == nil || ctx.Err() != nil || group == nil || group.VerifyDirectDenial(ctx, transcript) != nil || ctx.Err() != nil {
		return ErrWitnessUnavailable
	}
	return nil
}

func parseQualifiedAdapters(raw []byte, adminPublic ed25519.PublicKey, required []BoundaryRequirement, now time.Time, factories map[string]qualifiedFactory) (QualifiedAdapters, error) {
	var unavailable QualifiedAdapters
	if len(raw) == 0 || len(raw) > maxQualificationArtifactBytes || len(adminPublic) != ed25519.PublicKeySize || !validCompleteRequirements(required) || len(factories) == 0 || now.IsZero() {
		return unavailable, ErrWitnessUnavailable
	}
	var signed SignedQualificationRecord
	if json.Unmarshal(raw, &signed) != nil || len(signed.Signature) != ed25519.SignatureSize {
		return unavailable, ErrWitnessUnavailable
	}
	encoded, err := json.Marshal(signed)
	if err != nil || !bytes.Equal(encoded, raw) {
		return unavailable, ErrWitnessUnavailable
	}
	canonical, err := CanonicalQualificationRecord(signed.Payload)
	if err != nil || !ed25519.Verify(adminPublic, canonical, signed.Signature) {
		return unavailable, ErrWitnessUnavailable
	}
	expected := make(map[string]bool)
	for _, item := range required {
		expected[requirementQualificationKey(item)] = true
	}
	if len(expected) != len(signed.Payload.Entries) {
		return unavailable, ErrWitnessUnavailable
	}
	registry := NewQualifiedAdapters()
	byAdapter := make(map[string]map[string]DirectDenialVerifier)
	for _, entry := range signed.Payload.Entries {
		key := qualificationKey(entry)
		factory, exists := factories[entry.AdapterID]
		if !expected[key] || !exists || factory.implementationDigest != entry.ImplementationDigest || factory.new == nil || entry.ValidFrom.After(now) || !now.Before(entry.ExpiresAt) {
			return unavailable, ErrWitnessUnavailable
		}
		verifier := factory.new(entry)
		if verifier == nil {
			return unavailable, ErrWitnessUnavailable
		}
		if byAdapter[entry.AdapterID] == nil {
			byAdapter[entry.AdapterID] = make(map[string]DirectDenialVerifier)
		}
		byAdapter[entry.AdapterID][key] = verifier
	}
	for id, groups := range byAdapter {
		registry.Register(id, qualifiedGroupVerifier{groups: groups})
	}
	digest := sha256.Sum256(append(append([]byte(nil), canonical...), signed.Signature...))
	registry.sourceQualified = true
	registry.qualificationDigest = "sha256:" + hex.EncodeToString(digest[:])
	return registry, nil
}

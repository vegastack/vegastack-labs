package recovery

import (
	"context"
	"time"
)

// BoundaryRequirement is derived from applied server state by the recovery
// caller, never from a signed payload's own applicability declaration. Each
// required direct probe is a separate exact requirement.
type BoundaryRequirement struct {
	Kind             string `json:"kind"`
	SubjectID        string `json:"subjectId"`
	TargetID         string `json:"targetId"`
	AdapterID        string `json:"adapterId"`
	FormerIdentityID string `json:"formerIdentityId"`
	ProbeID          string `json:"probeId"`
}

type DirectDenialTranscript struct {
	Requirement    BoundaryRequirement `json:"requirement"`
	ObserverID     string              `json:"observerId"`
	ChallengeID    string              `json:"challengeId"`
	ResponseClass  string              `json:"responseClass"`
	ResponseDigest string              `json:"responseDigest"`
	ObservedAt     time.Time           `json:"observedAt"`
	ExpiresAt      time.Time           `json:"expiresAt"`
	SessionExpiry  time.Time           `json:"sessionExpiry"`
	Denied         bool                `json:"denied"`
}

// DirectDenialVerifier must authenticate an independently observed response
// and perform its typed endpoint check. Merely returning a signed status bit
// is not a qualifying implementation. No production verifier is registered.
type DirectDenialVerifier interface {
	VerifyDirectDenial(context.Context, DirectDenialTranscript) error
}

type QualifiedAdapters struct {
	entries             map[string]DirectDenialVerifier
	sourceQualified     bool
	qualificationDigest string
	qualificationExpiry time.Time
}

func NewQualifiedAdapters() QualifiedAdapters {
	return QualifiedAdapters{entries: make(map[string]DirectDenialVerifier)}
}

// Register is intended only for independently reviewed, typed adapters.
// Registration here never registers a production recovery source.
func (registry *QualifiedAdapters) Register(id string, verifier DirectDenialVerifier) {
	if registry == nil {
		return
	}
	// A post-qualification mutation cannot widen a sealed source registry.
	registry.sourceQualified = false
	registry.qualificationDigest = ""
	registry.qualificationExpiry = time.Time{}
	if !validWitnessToken(id) || verifier == nil {
		return
	}
	if registry.entries == nil {
		registry.entries = make(map[string]DirectDenialVerifier)
	}
	registry.entries[id] = verifier
}

var allowedProbes = map[string]map[string]bool{
	"host-service":      {"service-denied": true, "alternate-process-denied": true},
	"mesh":              {"registration-denied": true, "reenrollment-denied": true},
	"ssh":               {"new-auth-denied": true, "open-session-denied": true},
	"secret-resolver":   {"resolve-denied": true, "cached-material-denied": true},
	"provider-mutation": {"mutation-denied": true, "outstanding-session-denied": true},
	"backup-writer":     {"new-payload-denied": true, "retained-alteration-denied": true, "outstanding-session-denied": true},
	"audit-writer":      {"append-denied": true, "export-denied": true},
}

// VerifyBoundarySet proves exact coverage relative to requirements obtained
// from current applied state. Its result is conditional on every registered
// adapter doing a real independently attributed direct-denial verification.
func VerifyBoundarySet(ctx context.Context, required []BoundaryRequirement, payload WitnessPayload, qualified QualifiedAdapters, now time.Time) error {
	if ctx == nil || ctx.Err() != nil || len(required) == 0 || len(required) > 256 || len(payload.Transcripts) != len(required) || !validWitnessToken(payload.Binding.ChallengeID) || !validWitnessToken(payload.WitnessInstanceID) {
		return ErrWitnessUnavailable
	}
	now = now.UTC()
	expected := make(map[BoundaryRequirement]bool, len(required))
	groups := make(map[BoundaryRequirement]map[string]bool)
	for _, item := range required {
		if !validBoundaryRequirement(item) || expected[item] {
			return ErrWitnessUnavailable
		}
		expected[item] = true
		group := item
		group.ProbeID = ""
		if groups[group] == nil {
			groups[group] = make(map[string]bool)
		}
		groups[group][item.ProbeID] = true
	}
	for group, probes := range groups {
		if len(probes) != len(allowedProbes[group.Kind]) {
			return ErrWitnessUnavailable
		}
	}
	seen := make(map[BoundaryRequirement]bool, len(required))
	for _, proof := range payload.Transcripts {
		if !expected[proof.Requirement] || seen[proof.Requirement] || proof.ObserverID == payload.Binding.FormerInstanceID || proof.ObserverID == payload.Binding.ReplacementInstanceID || proof.ObserverID == proof.Requirement.FormerIdentityID || !validWitnessToken(proof.ObserverID) || proof.ChallengeID != payload.Binding.ChallengeID || proof.ResponseClass != "direct-denial" || !witnessDigest.MatchString(proof.ResponseDigest) || !proof.Denied {
			return ErrWitnessUnavailable
		}
		if proof.ObservedAt.IsZero() || proof.ObservedAt.After(now) || now.Sub(proof.ObservedAt) > maxWitnessAge || !now.Before(proof.ExpiresAt) || proof.ExpiresAt.After(payload.ExpiresAt) || !now.Before(proof.SessionExpiry) || proof.SessionExpiry.Before(proof.ObservedAt) {
			return ErrWitnessUnavailable
		}
		verifier, ok := qualified.entries[proof.Requirement.AdapterID]
		if !ok || verifier == nil || verifier.VerifyDirectDenial(ctx, proof) != nil || ctx.Err() != nil {
			return ErrWitnessUnavailable
		}
		seen[proof.Requirement] = true
	}
	return nil
}

// VerifyWitnessBundle keeps signature, exact binding, and complete direct
// denial coverage together. A caller must additionally verify one-use custody
// and current recovery authority before treating this as a recovery proof.
func VerifyWitnessBundle(ctx context.Context, pin PinnedWitness, expected WitnessBinding, signed SignedWitness, required []BoundaryRequirement, qualified QualifiedAdapters, now time.Time) error {
	if err := VerifySignedWitness(ctx, pin, expected, signed, now); err != nil {
		return err
	}
	return VerifyBoundarySet(ctx, required, signed.Payload, qualified, now)
}

func validBoundaryRequirement(item BoundaryRequirement) bool {
	for _, token := range []string{item.Kind, item.SubjectID, item.TargetID, item.AdapterID, item.FormerIdentityID, item.ProbeID} {
		if !validWitnessToken(token) {
			return false
		}
	}
	return allowedProbes[item.Kind][item.ProbeID]
}

// validCompleteRequirements accepts only a bounded, exact direct-probe set.
// Its authenticated source is still the administrator manifest; this helper
// prevents that source from accidentally sealing a partial probe group.
func validCompleteRequirements(required []BoundaryRequirement) bool {
	if len(required) == 0 || len(required) > 256 {
		return false
	}
	seen := make(map[BoundaryRequirement]bool, len(required))
	groups := make(map[BoundaryRequirement]map[string]bool)
	for _, item := range required {
		if !validBoundaryRequirement(item) || seen[item] {
			return false
		}
		seen[item] = true
		group := item
		group.ProbeID = ""
		if groups[group] == nil {
			groups[group] = make(map[string]bool)
		}
		groups[group][item.ProbeID] = true
	}
	for group, probes := range groups {
		if len(probes) != len(allowedProbes[group.Kind]) {
			return false
		}
	}
	return true
}

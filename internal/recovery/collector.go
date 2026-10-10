package recovery

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"io"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter/recoverydenial"
)

// LoadSystemWitnessAdapters exposes probes only from the existing protected,
// administrator-qualified registry for this exact authenticated manifest.
func LoadSystemWitnessAdapters(ctx context.Context, pin PinnedWitness, binding WitnessBinding, now time.Time) (map[string]recoverydenial.Adapter, error) {
	qualified, err := LoadSystemQualifiedAdapters(ctx, pin.Requirements, now)
	if err != nil {
		return nil, ErrWitnessUnavailable
	}
	return qualifiedWitnessAdapters(pin, binding, qualified, time.Now)
}

func qualifiedWitnessAdapters(pin PinnedWitness, binding WitnessBinding, qualified QualifiedAdapters, clock func() time.Time) (map[string]recoverydenial.Adapter, error) {
	if clock == nil || !pin.matchesBinding(binding) || !validCompleteRequirements(pin.Requirements) {
		return nil, ErrWitnessUnavailable
	}
	now := clock().UTC()
	digest, expiry, err := HostGenerationQualification(qualified, now)
	if err != nil || digest != binding.FenceQualificationDigest || qualified.adminRootDigest != pin.adminRootDigest || !now.Before(pin.ExpiresAt) {
		return nil, ErrWitnessUnavailable
	}
	if pin.ExpiresAt.Before(expiry) {
		expiry = pin.ExpiresAt
	}
	allowed := make(map[BoundaryRequirement]bool, len(pin.Requirements))
	groups := map[string]bool{}
	adapters := map[string]recoverydenial.Adapter{}
	for _, requirement := range pin.Requirements {
		group, ok := qualified.entries[requirement.AdapterID].(qualifiedGroupVerifier)
		key := requirementQualificationKey(requirement)
		if !ok || group.groups[key] == nil {
			return nil, ErrWitnessUnavailable
		}
		if _, ok := group.groups[key].(hostGenerationProber); !ok {
			return nil, ErrWitnessUnavailable
		}
		allowed[requirement] = true
		groups[key] = true
		adapters[requirement.AdapterID] = qualifiedWitnessAdapter{prober: group, allowed: allowed, expiresAt: expiry, clock: clock}
	}
	count := 0
	for _, verifier := range qualified.entries {
		group, ok := verifier.(qualifiedGroupVerifier)
		if !ok {
			return nil, ErrWitnessUnavailable
		}
		count += len(group.groups)
	}
	if count != len(groups) {
		return nil, ErrWitnessUnavailable
	}
	return adapters, nil
}

type qualifiedWitnessAdapter struct {
	prober    hostGenerationProber
	allowed   map[BoundaryRequirement]bool
	expiresAt time.Time
	clock     func() time.Time
}

func (adapter qualifiedWitnessAdapter) Probe(ctx context.Context, challenge recoverydenial.Challenge) (recoverydenial.Result, error) {
	requirement := BoundaryRequirement{Kind: challenge.Kind, SubjectID: challenge.SubjectID, TargetID: challenge.TargetID, AdapterID: challenge.AdapterID, FormerIdentityID: challenge.FormerIdentityID, ProbeID: challenge.ProbeID}
	if ctx == nil || ctx.Err() != nil || adapter.clock == nil || adapter.prober == nil || !adapter.allowed[requirement] || !adapter.clock().UTC().Before(adapter.expiresAt) {
		return recoverydenial.Result{}, ErrWitnessUnavailable
	}
	if challenge.Deadline.After(adapter.expiresAt) {
		challenge.Deadline = adapter.expiresAt
	}
	return adapter.prober.probeHostGeneration(ctx, challenge)
}

// CollectRequest is a finite custodian-side input. Pin must originate from an
// administrator-authenticated protected manifest. Required must exactly match
// the manifest's independently sealed set; the replacement rederives it.
type CollectRequest struct {
	Pin        PinnedWitness
	Binding    WitnessBinding
	Required   []BoundaryRequirement
	Adapters   map[string]recoverydenial.Adapter
	SigningKey io.ReadCloser
	Material   io.ReadCloser
	Now        func() time.Time
}

// CollectWitness never registers a production recovery source. It owns both
// private readers and returns only a signed public bundle and sealed envelope.
func CollectWitness(ctx context.Context, request CollectRequest) (signed SignedWitness, envelope ProtectedEnvelope, err error) {
	var seed [33]byte
	defer func() {
		wipePrivate(seed[:])
		if recover() != nil {
			signed, envelope, err = SignedWitness{}, ProtectedEnvelope{}, ErrWitnessUnavailable
		}
	}()
	if request.SigningKey != nil {
		defer request.SigningKey.Close()
	}
	if request.Material != nil {
		defer request.Material.Close()
	}
	if ctx == nil || ctx.Err() != nil || request.SigningKey == nil || request.Material == nil || request.Now == nil || !request.Pin.matchesBinding(request.Binding) || !validCompleteRequirements(request.Pin.Requirements) || len(request.Required) != len(request.Pin.Requirements) {
		return SignedWitness{}, ProtectedEnvelope{}, ErrWitnessUnavailable
	}
	for index := range request.Required {
		if request.Required[index] != request.Pin.Requirements[index] {
			return SignedWitness{}, ProtectedEnvelope{}, ErrWitnessUnavailable
		}
	}
	stopKey := context.AfterFunc(ctx, func() { _ = request.SigningKey.Close() })
	defer stopKey()
	stopMaterial := context.AfterFunc(ctx, func() { _ = request.Material.Close() })
	defer stopMaterial()
	now := request.Now().UTC()
	if now.IsZero() {
		return SignedWitness{}, ProtectedEnvelope{}, ErrWitnessUnavailable
	}
	deadline := now.Add(maxWitnessAge)
	if request.Pin.ExpiresAt.Before(deadline) {
		deadline = request.Pin.ExpiresAt
	}
	if !now.Before(deadline) {
		return SignedWitness{}, ProtectedEnvelope{}, ErrWitnessUnavailable
	}
	seen := make(map[BoundaryRequirement]bool, len(request.Required))
	groups := make(map[BoundaryRequirement]map[string]bool)
	transcripts := make([]DirectDenialTranscript, 0, len(request.Required))
	qualified := NewQualifiedAdapters()
	for _, requirement := range request.Required {
		if !validBoundaryRequirement(requirement) || seen[requirement] {
			return SignedWitness{}, ProtectedEnvelope{}, ErrWitnessUnavailable
		}
		seen[requirement] = true
		group := requirement
		group.ProbeID = ""
		if groups[group] == nil {
			groups[group] = make(map[string]bool)
		}
		groups[group][requirement.ProbeID] = true
		adapter := request.Adapters[requirement.AdapterID]
		if adapter == nil {
			return SignedWitness{}, ProtectedEnvelope{}, ErrWitnessUnavailable
		}
		challenge := recoverydenial.Challenge{ChallengeID: request.Binding.ChallengeID, Kind: requirement.Kind, SubjectID: requirement.SubjectID, TargetID: requirement.TargetID, AdapterID: requirement.AdapterID, FormerIdentityID: requirement.FormerIdentityID, ProbeID: requirement.ProbeID, Deadline: deadline}
		result, probeErr := adapter.Probe(ctx, challenge)
		if probeErr != nil || recoverydenial.ValidateResult(ctx, challenge, result, request.Now().UTC()) != nil || result.ObserverID == request.Binding.FormerInstanceID || result.ObserverID == request.Binding.ReplacementInstanceID {
			return SignedWitness{}, ProtectedEnvelope{}, ErrWitnessUnavailable
		}
		if result.ExpiresAt.Before(deadline) {
			deadline = result.ExpiresAt
		}
		if result.SessionExpiry.Before(deadline) {
			deadline = result.SessionExpiry
		}
		transcripts = append(transcripts, DirectDenialTranscript{Requirement: requirement, ObserverID: result.ObserverID, ChallengeID: result.ChallengeID, ResponseClass: result.ResponseClass, ResponseDigest: result.ResponseDigest, ObservedAt: result.ObservedAt, ExpiresAt: result.ExpiresAt, SessionExpiry: result.SessionExpiry, Denied: result.Denied})
		qualified.Register(requirement.AdapterID, collectedProbeVerifier{adapter: adapter, now: request.Now})
	}
	for group, probes := range groups {
		if len(probes) != len(allowedProbes[group.Kind]) {
			return SignedWitness{}, ProtectedEnvelope{}, ErrWitnessUnavailable
		}
	}
	if !request.Now().UTC().Before(deadline) {
		return SignedWitness{}, ProtectedEnvelope{}, ErrWitnessUnavailable
	}
	for index := range transcripts {
		if transcripts[index].ExpiresAt.After(deadline) {
			transcripts[index].ExpiresAt = deadline
		}
	}
	payload := WitnessPayload{Binding: request.Binding, KeyID: request.Pin.KeyID, WitnessInstanceID: request.Pin.WitnessInstanceID, IssuedAt: now, ObservedAt: now, ExpiresAt: deadline, Transcripts: transcripts}
	if VerifyBoundarySet(ctx, request.Required, payload, qualified, request.Now().UTC()) != nil {
		return SignedWitness{}, ProtectedEnvelope{}, ErrWitnessUnavailable
	}
	length, readErr := readCustodyBounded(request.SigningKey, seed[:], 32)
	if readErr != nil || length != 32 || ctx.Err() != nil {
		return SignedWitness{}, ProtectedEnvelope{}, ErrWitnessUnavailable
	}
	private := ed25519.NewKeyFromSeed(seed[:32])
	defer wipePrivate(private)
	if subtle.ConstantTimeCompare(private.Public().(ed25519.PublicKey), request.Pin.PublicKey) != 1 {
		return SignedWitness{}, ProtectedEnvelope{}, ErrWitnessUnavailable
	}
	sealed, sealErr := SealProtectedEnvelope(ctx, request.Pin, request.Binding, request.Material)
	if sealErr != nil || ctx.Err() != nil {
		return SignedWitness{}, ProtectedEnvelope{}, ErrWitnessUnavailable
	}
	canonical, canonicalErr := CanonicalWitnessPayload(payload)
	if canonicalErr != nil {
		return SignedWitness{}, ProtectedEnvelope{}, ErrWitnessUnavailable
	}
	output := SignedWitness{Payload: payload, Signature: ed25519.Sign(private, canonical)}
	if VerifySignedWitness(ctx, request.Pin, request.Binding, output, request.Now().UTC()) != nil {
		return SignedWitness{}, ProtectedEnvelope{}, ErrWitnessUnavailable
	}
	return output, sealed, nil
}

type collectedProbeVerifier struct {
	adapter recoverydenial.Adapter
	now     func() time.Time
}

func (verifier collectedProbeVerifier) VerifyDirectDenial(ctx context.Context, transcript DirectDenialTranscript) error {
	challenge := recoverydenial.Challenge{ChallengeID: transcript.ChallengeID, Kind: transcript.Requirement.Kind, SubjectID: transcript.Requirement.SubjectID, TargetID: transcript.Requirement.TargetID, AdapterID: transcript.Requirement.AdapterID, FormerIdentityID: transcript.Requirement.FormerIdentityID, ProbeID: transcript.Requirement.ProbeID, Deadline: transcript.ExpiresAt}
	result, err := verifier.adapter.Probe(ctx, challenge)
	if err != nil || recoverydenial.ValidateResult(ctx, challenge, result, verifier.now().UTC()) != nil || result.ObserverID != transcript.ObserverID || result.ResponseDigest != transcript.ResponseDigest || !result.Denied {
		return ErrWitnessUnavailable
	}
	return nil
}

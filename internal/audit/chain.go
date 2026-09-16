package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// ChainLink is an envelope around the existing v1.0 canonical event, not a
// replacement audit event. Its digest binds the event payload to one instance,
// recovery epoch, ordered segment position, predecessor, and trusted context.
type ChainLink struct {
	InstanceID      string
	RecoveryEpoch   int64
	EventID         EventID
	SegmentSequence int64
	PreviousDigest  Fingerprint
	PayloadDigest   Fingerprint
	ContextDigest   Fingerprint
	Context         ContextIDs
	LinkDigest      Fingerprint
	PreAnchor       bool
	// Genesis-only inputs are retained so an independent verifier can
	// reconstruct the first link rather than trusting a bare digest.
	PriorCheckpoint  Fingerprint
	RecoveryDecision Fingerprint
}

// ChainRange is the exact, ordered set of links committed by a checkpoint.
type ChainRange struct {
	FirstEventID EventID
	LastEventID  EventID
	Links        []ChainLink
	RangeDigest  Fingerprint
}

// ContextIDs are bounded identifiers supplied by trusted event producers.
// They are not an open payload or a place for provider responses or secrets.
type ContextIDs struct {
	RunID            string
	PlanID           string
	ProviderNativeID string
}

const (
	chainLinkDomain = "vegastack-labs.dev/audit-chain-link/v1"
	contextDomain   = "vegastack-labs.dev/audit-chain-context/v1"
	genesisDomain   = "vegastack-labs.dev/audit-chain-genesis/v1"
)

// CanonicalContext uses fixed JSON field order and rejects free-form or
// secret-like identifiers before they can become part of a public digest.
func CanonicalContext(ids ContextIDs) ([]byte, Fingerprint, error) {
	for _, value := range []string{ids.RunID, ids.PlanID, ids.ProviderNativeID} {
		if value != "" && !validToken(value, 128) {
			return nil, "", errInvalid
		}
	}
	data, err := json.Marshal(struct {
		Domain           string `json:"domain"`
		RunID            string `json:"runId"`
		PlanID           string `json:"planId"`
		ProviderNativeID string `json:"providerNativeId"`
	}{contextDomain, ids.RunID, ids.PlanID, ids.ProviderNativeID})
	if err != nil {
		return nil, "", errInvalid
	}
	return data, hashChainBytes(data), nil
}

// MakeChainLink hashes the already versioned v1.0 canonical event without
// changing that event's bytes or schema. A malformed event or predecessor
// fails closed, so a chain writer cannot silently start a different history.
func MakeChainLink(event Event, ids ContextIDs, instanceID string, segmentSequence int64, previous Fingerprint, preAnchor bool) (ChainLink, error) {
	if !validToken(instanceID, 128) || segmentSequence <= 0 || !ValidFingerprint(previous) {
		return ChainLink{}, errInvalid
	}
	_, payloadDigest, err := CanonicalEvent(event)
	if err != nil {
		return ChainLink{}, err
	}
	_, contextDigest, err := CanonicalContext(ids)
	if err != nil {
		return ChainLink{}, err
	}
	link := ChainLink{
		InstanceID: instanceID, RecoveryEpoch: event.RecoveryEpoch, EventID: event.EventID,
		SegmentSequence: segmentSequence, PreviousDigest: previous, PayloadDigest: payloadDigest,
		ContextDigest: contextDigest, Context: ids, PreAnchor: preAnchor,
	}
	data, err := json.Marshal(struct {
		Domain          string      `json:"domain"`
		InstanceID      string      `json:"instanceId"`
		RecoveryEpoch   int64       `json:"recoveryEpoch"`
		EventID         EventID     `json:"eventId"`
		SegmentSequence int64       `json:"segmentSequence"`
		PreviousDigest  Fingerprint `json:"previousDigest"`
		PayloadDigest   Fingerprint `json:"payloadDigest"`
		ContextDigest   Fingerprint `json:"contextDigest"`
		PreAnchor       bool        `json:"preAnchor"`
	}{chainLinkDomain, link.InstanceID, link.RecoveryEpoch, link.EventID, link.SegmentSequence,
		link.PreviousDigest, link.PayloadDigest, link.ContextDigest, link.PreAnchor})
	if err != nil {
		return ChainLink{}, errInvalid
	}
	link.LinkDigest = hashChainBytes(data)
	return link, nil
}

// DigestChainRange binds the ordered link digests and exact endpoints.
func DigestChainRange(links []ChainLink) (Fingerprint, error) {
	if len(links) == 0 {
		return "", errInvalid
	}
	for index, link := range links {
		if !ValidFingerprint(link.LinkDigest) || link.EventID <= 0 || (index > 0 && link.EventID <= links[index-1].EventID) {
			return "", errInvalid
		}
	}
	data, err := json.Marshal(struct {
		Domain string        `json:"domain"`
		First  EventID       `json:"firstEventId"`
		Last   EventID       `json:"lastEventId"`
		Links  []Fingerprint `json:"linkDigests"`
	}{"vegastack-labs.dev/audit-chain-range/v1", links[0].EventID, links[len(links)-1].EventID, chainDigests(links)})
	if err != nil {
		return "", errInvalid
	}
	return hashChainBytes(data), nil
}

func chainDigests(links []ChainLink) []Fingerprint {
	result := make([]Fingerprint, len(links))
	for index := range links {
		result[index] = links[index].LinkDigest
	}
	return result
}

// GenesisLink starts a distinct epoch segment. Invalid bindings yield an
// unusable zero link; the writer must validate the digest before persisting it.
// The caller supplies explicit fingerprints for the prior known checkpoint and
// approved recovery decision, including defined zero fingerprints at setup.
func GenesisLink(instanceID string, epoch int64, priorCheckpoint, recoveryDecision Fingerprint) ChainLink {
	if !validToken(instanceID, 128) || epoch < 0 || !ValidFingerprint(priorCheckpoint) || !ValidFingerprint(recoveryDecision) {
		return ChainLink{}
	}
	data, err := json.Marshal(struct {
		Domain           string      `json:"domain"`
		InstanceID       string      `json:"instanceId"`
		RecoveryEpoch    int64       `json:"recoveryEpoch"`
		PriorCheckpoint  Fingerprint `json:"priorCheckpoint"`
		RecoveryDecision Fingerprint `json:"recoveryDecision"`
	}{genesisDomain, instanceID, epoch, priorCheckpoint, recoveryDecision})
	if err != nil {
		return ChainLink{}
	}
	return ChainLink{
		InstanceID: instanceID, RecoveryEpoch: epoch, PriorCheckpoint: priorCheckpoint,
		RecoveryDecision: recoveryDecision, LinkDigest: hashChainBytes(data),
	}
}

func hashChainBytes(data []byte) Fingerprint {
	sum := sha256.Sum256(data)
	return Fingerprint("sha256:" + hex.EncodeToString(sum[:]))
}

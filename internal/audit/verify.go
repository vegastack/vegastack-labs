package audit

import (
	"crypto/ed25519"
	"errors"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

type LocalResult struct {
	Status        string
	ReasonCode    string
	InstanceID    string
	RecoveryEpoch int64
	LocalDigest   Fingerprint
	LastSequence  int64
	PreAnchor     bool
	LastAnchored  *generated.AuditCheckpoint
	AnchoredRange ChainRange
	Namespace     string
}

type VerificationResult struct {
	Status            string
	ReasonCode        string
	LocalDigest       Fingerprint
	IndependentDigest Fingerprint
	IndependentMatch  bool
	LastSequence      int64
	PreAnchor         bool
}

func VerifyLocal(links []ChainLink, events []Event, checkpoints []generated.AuditCheckpoint) (LocalResult, error) {
	incident := func(reason string) (LocalResult, error) {
		return LocalResult{Status: "incident", ReasonCode: reason}, errors.New(reason)
	}
	if len(links) == 0 && len(events) == 0 {
		return LocalResult{Status: "degraded", ReasonCode: "audit-history-empty", LocalDigest: hashChainBytes(nil)}, nil
	}
	if len(links) == 0 || len(links) != len(events) {
		return incident("audit-history-gap")
	}
	for index := range links {
		link, event := links[index], events[index]
		if link.EventID != event.EventID || link.RecoveryEpoch != event.RecoveryEpoch || link.EventID <= 0 || !ValidFingerprint(link.PreviousDigest) || !ValidFingerprint(link.LinkDigest) {
			return incident("audit-history-binding")
		}
		if index > 0 {
			prior := links[index-1]
			if link.EventID != prior.EventID+1 {
				return incident("audit-history-gap")
			}
			if link.RecoveryEpoch == prior.RecoveryEpoch {
				if link.InstanceID != prior.InstanceID || link.SegmentSequence != prior.SegmentSequence+1 || link.PreviousDigest != prior.LinkDigest {
					return incident("audit-history-fork")
				}
			} else if link.RecoveryEpoch != prior.RecoveryEpoch+1 || link.SegmentSequence != 1 {
				return incident("audit-history-epoch")
			}
		}
		_, payloadDigest, err := CanonicalEvent(event)
		if err != nil || payloadDigest != link.PayloadDigest {
			return incident("audit-history-payload")
		}
		_, contextDigest, err := CanonicalContext(link.Context)
		if err != nil || contextDigest != link.ContextDigest {
			return incident("audit-history-context")
		}
		rebuilt, err := MakeChainLink(event, link.Context, link.InstanceID, link.SegmentSequence, link.PreviousDigest, link.PreAnchor)
		if err != nil || rebuilt.LinkDigest != link.LinkDigest {
			return incident("audit-history-link")
		}
	}
	last := links[len(links)-1]
	result := LocalResult{Status: "degraded", ReasonCode: "no-independent-anchor", InstanceID: last.InstanceID, RecoveryEpoch: last.RecoveryEpoch, LocalDigest: last.LinkDigest, LastSequence: last.SegmentSequence, PreAnchor: last.PreAnchor}
	for index := range checkpoints {
		checkpoint := checkpoints[index]
		if checkpoint.Status != "anchored" {
			continue
		}
		if checkpoint.FirstEventID <= 0 || checkpoint.LastEventID < checkpoint.FirstEventID || checkpoint.LastEventID > int64(len(links)) || checkpoint.SignatureDigest == nil || checkpoint.ExportReceiptDigest == nil || checkpoint.IndependentReadDigest == nil {
			return incident("audit-checkpoint-invalid")
		}
		start, end := int(checkpoint.FirstEventID-1), int(checkpoint.LastEventID)
		rangeLinks := append([]ChainLink(nil), links[start:end]...)
		digest, err := DigestChainRange(rangeLinks)
		if err != nil || string(digest) != checkpoint.ChainDigest || rangeLinks[0].SegmentSequence != checkpoint.FirstSegmentSequence || rangeLinks[len(rangeLinks)-1].SegmentSequence != checkpoint.LastSegmentSequence || rangeLinks[0].InstanceID != checkpoint.InstanceID || rangeLinks[0].RecoveryEpoch != checkpoint.RecoveryEpoch {
			return incident("audit-checkpoint-range")
		}
		if result.LastAnchored == nil || checkpoint.LastEventID > result.LastAnchored.LastEventID {
			copy := checkpoint
			result.LastAnchored = &copy
			result.AnchoredRange = ChainRange{FirstEventID: EventID(checkpoint.FirstEventID), LastEventID: EventID(checkpoint.LastEventID), Links: rangeLinks, RangeDigest: digest}
			result.Status, result.ReasonCode, result.PreAnchor = "anchored", "local-anchor-valid", checkpoint.PreAnchor
		}
	}
	return result, nil
}

func CompareIndependent(local LocalResult, remote IndependentCheckpoint, key PublicKey) (VerificationResult, error) {
	result := VerificationResult{Status: local.Status, ReasonCode: local.ReasonCode, LocalDigest: local.LocalDigest, LastSequence: local.LastSequence, PreAnchor: local.PreAnchor}
	if local.LastAnchored == nil {
		return result, nil
	}
	cp := local.LastAnchored
	result.IndependentDigest = remote.IndependentRead
	if remote.LastEventID > EventID(cp.LastEventID) {
		result.Status, result.ReasonCode = "incident", "independent-checkpoint-ahead"
		return result, errors.New(result.ReasonCode)
	}
	if remote.LastEventID < EventID(cp.LastEventID) {
		result.Status, result.ReasonCode = "degraded", "independent-checkpoint-stale"
		return result, nil
	}
	reference := credentialref.Reference{ID: cp.SignerReferenceID, Consumer: "core.audit.signer"}
	if remote.CheckpointID != cp.CheckpointID || remote.InstanceID != cp.InstanceID || remote.RecoveryEpoch != cp.RecoveryEpoch || remote.LastSequence != cp.LastSegmentSequence || remote.ChainDigest != Fingerprint(cp.ChainDigest) || remote.SignerReference != reference || remote.MaterialVersion != cp.SignerMaterialVersion || local.Namespace != "" && remote.Namespace != local.Namespace || remote.ExportReceipt != Fingerprint(*cp.ExportReceiptDigest) || remote.IndependentRead != Fingerprint(*cp.IndependentReadDigest) || remote.Signature.PublicKeyID != key.ID || remote.Signature.Digest != SignatureDigest(remote.Signature.Bytes) {
		result.Status, result.ReasonCode = "incident", "independent-checkpoint-conflict"
		return result, errors.New(result.ReasonCode)
	}
	signed, err := CheckpointBindingDigest(EventID(cp.FirstEventID), EventID(cp.LastEventID), cp.FirstSegmentSequence, cp.LastSegmentSequence, Fingerprint(cp.ChainDigest), cp.InstanceID, cp.RecoveryEpoch, reference, cp.SignerMaterialVersion, remote.Namespace)
	if err != nil || signed != remote.SignedDigest || len(key.Bytes) != ed25519.PublicKeySize || !ed25519.Verify(ed25519.PublicKey(key.Bytes), []byte(signed), remote.Signature.Bytes) {
		result.Status, result.ReasonCode = "incident", "independent-signature-invalid"
		return result, errors.New(result.ReasonCode)
	}
	result.Status, result.ReasonCode, result.IndependentMatch = "anchored", "independent-match", true
	return result, nil
}

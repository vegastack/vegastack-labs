package recovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type LostInterval struct {
	FromEventID, ThroughEventID int64
	From, Through               time.Time
	HumanAcknowledgementID      string
}

type AuditContinuity struct {
	Strategy                                                           string
	LocalLastEventID, IndependentLastEventID                           int64
	IndependentCheckpointDigest, RecoveredSuffixDigest, DecisionDigest string
	LostInterval                                                       *LostInterval
}

type AuditSuffixReader interface {
	ReadAuditSuffix(context.Context, audit.EventID, audit.EventID) (store.CanonicalAuditSuffix, error)
}

type AuditLossAcknowledgementVerifier interface {
	VerifyAuditLoss(context.Context, generated.RestoreAuditDecision) error
}

type ContinuityResolver struct {
	Suffix           AuditSuffixReader
	Acknowledgements AuditLossAcknowledgementVerifier
}

func (resolver ContinuityResolver) Resolve(ctx context.Context, source VerifiedSource, decision *generated.RestoreAuditDecision) (AuditContinuity, error) {
	current := source.Audit
	if ctx == nil || ctx.Err() != nil || current.LocalLastEventID < 0 || current.IndependentLastEventID < current.LocalLastEventID || !restoreDigest.MatchString(current.IndependentCheckpointDigest) {
		return AuditContinuity{}, failure.New(generated.ErrorCodePrerequisiteBlocked, "restore-audit-continuity", false)
	}
	if current.LocalLastEventID == current.IndependentLastEventID {
		if decision != nil && decision.Strategy != "matched" {
			return AuditContinuity{}, failure.New(generated.ErrorCodeInputInvalid, "restore-audit-decision", false)
		}
		current.Strategy = "matched"
		current.DecisionDigest = auditDecisionDigest(current.Strategy, current.LocalLastEventID, current.IndependentLastEventID, current.IndependentCheckpointDigest, "", nil)
		return current, nil
	}
	if decision == nil {
		return AuditContinuity{}, failure.New(generated.ErrorCodeRecoveryRequired, "restore-audit-suffix", false)
	}
	if decision.Schema != generated.SchemaIDRestoreAuditDecision || decision.SchemaVersion != "1.1.0" || decision.LocalLastEventID != current.LocalLastEventID || decision.IndependentLastEventID != current.IndependentLastEventID || decision.IndependentCheckpointDigest != current.IndependentCheckpointDigest {
		return AuditContinuity{}, failure.New(generated.ErrorCodeInputInvalid, "restore-audit-decision", false)
	}
	switch decision.Strategy {
	case "recovered-suffix":
		if resolver.Suffix == nil || decision.LostFromEventID != nil || decision.LostThroughEventID != nil || decision.LostFromTime != nil || decision.LostThroughTime != nil || decision.HumanAcknowledgementID != nil {
			return AuditContinuity{}, failure.New(generated.ErrorCodePrerequisiteBlocked, "restore-audit-suffix", false)
		}
		suffix, err := resolver.Suffix.ReadAuditSuffix(ctx, audit.EventID(current.LocalLastEventID+1), audit.EventID(current.IndependentLastEventID))
		expectedCount := int(current.IndependentLastEventID - current.LocalLastEventID)
		if err != nil || !audit.ValidFingerprint(suffix.Digest) || !audit.ValidFingerprint(suffix.Chain.RangeDigest) || suffix.Chain.FirstEventID != audit.EventID(current.LocalLastEventID+1) || suffix.Chain.LastEventID != audit.EventID(current.IndependentLastEventID) || len(suffix.Events) != expectedCount || len(suffix.Chain.Links) != expectedCount {
			return AuditContinuity{}, failure.New(generated.ErrorCodePrerequisiteBlocked, "restore-audit-suffix", false)
		}
		if _, err := audit.VerifyLocal(suffix.Chain.Links, suffix.Events, nil); err != nil {
			return AuditContinuity{}, failure.New(generated.ErrorCodePrerequisiteBlocked, "restore-audit-suffix", false)
		}
		current.Strategy, current.RecoveredSuffixDigest = "recovered-suffix", string(suffix.Digest)
		current.DecisionDigest = auditDecisionDigest(current.Strategy, current.LocalLastEventID, current.IndependentLastEventID, current.IndependentCheckpointDigest, current.RecoveredSuffixDigest, nil)
	case "accepted-loss":
		if resolver.Acknowledgements == nil || decision.LostFromEventID == nil || decision.LostThroughEventID == nil || decision.LostFromTime == nil || decision.LostThroughTime == nil || decision.HumanAcknowledgementID == nil ||
			*decision.LostFromEventID != current.LocalLastEventID+1 || *decision.LostThroughEventID != current.IndependentLastEventID {
			return AuditContinuity{}, failure.New(generated.ErrorCodePrerequisiteBlocked, "restore-audit-loss", false)
		}
		from, fromErr := time.Parse(time.RFC3339, *decision.LostFromTime)
		through, throughErr := time.Parse(time.RFC3339, *decision.LostThroughTime)
		if fromErr != nil || throughErr != nil || through.Before(from) || resolver.Acknowledgements.VerifyAuditLoss(ctx, *decision) != nil {
			return AuditContinuity{}, failure.New(generated.ErrorCodeAuthorizationDenied, "restore-audit-loss", false)
		}
		lost := &LostInterval{FromEventID: *decision.LostFromEventID, ThroughEventID: *decision.LostThroughEventID, From: from, Through: through, HumanAcknowledgementID: *decision.HumanAcknowledgementID}
		current.Strategy, current.LostInterval = "accepted-loss", lost
		current.DecisionDigest = auditDecisionDigest(current.Strategy, current.LocalLastEventID, current.IndependentLastEventID, current.IndependentCheckpointDigest, "", lost)
	default:
		return AuditContinuity{}, failure.New(generated.ErrorCodeInputInvalid, "restore-audit-decision", false)
	}
	if decision.DecisionDigest != current.DecisionDigest {
		return AuditContinuity{}, failure.New(generated.ErrorCodePlanStale, "restore-audit-decision", false)
	}
	return current, nil
}

func auditDecisionDigest(strategy string, local, independent int64, checkpoint, suffix string, lost *LostInterval) string {
	value := struct {
		Domain, Strategy   string
		Local, Independent int64
		Checkpoint, Suffix string
		Lost               *LostInterval
	}{"vegastack-labs.dev/restore-audit-decision/v1", strategy, local, independent, checkpoint, suffix, lost}
	raw, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

package recovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter/recoverydenial"
)

// HostGenerationFenceBinding is derived from durable frozen ownership and an
// exact execution. Nonce and ReceiptID must be persisted before probing and
// consumed by the caller's existing execution transaction, never by this reader.
type HostGenerationFenceBinding struct {
	ReplacementID, ControllerInstanceID, OldHostID, NewHostID                  string
	OldIdentityDigest, NewIdentityDigest, FrozenAliasesDigest, AuthorityDigest string
	PlanID, PlanDigest, RunID, StepID, LeaseID                                 string
	RequirementsDigest, QualificationDigest, Nonce, ReceiptID                  string
	RecoveryEpoch, PriorGeneration, NextGeneration                             int64
	IssuedAt, Deadline                                                         time.Time
}

type HostGenerationFenceReceipt struct {
	Binding     HostGenerationFenceBinding
	ChallengeID string
	Transcripts []DirectDenialTranscript
	ExpiresAt   time.Time
	Digest      string
}

type hostGenerationProber interface {
	probeHostGeneration(context.Context, recoverydenial.Challenge) (recoverydenial.Result, error)
}

func fenceDigest(v any) string {
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func HostGenerationRequirementsDigest(required []BoundaryRequirement) (string, error) {
	if !validCompleteRequirements(required) {
		return "", ErrWitnessUnavailable
	}
	copied := append([]BoundaryRequirement(nil), required...)
	sort.Slice(copied, func(i, j int) bool {
		return requirementQualificationKey(copied[i])+"\x00"+copied[i].ProbeID < requirementQualificationKey(copied[j])+"\x00"+copied[j].ProbeID
	})
	return fenceDigest(copied), nil
}

// HostGenerationChallengeID binds the entire frozen execution to the existing
// direct-denial protocol without pretending to replace a controller instance.
func HostGenerationChallengeID(b HostGenerationFenceBinding) string {
	return "host-generation/" + fenceDigest(b)[7:]
}

func VerifyHostGenerationFences(ctx context.Context, b HostGenerationFenceBinding, required []BoundaryRequirement, q QualifiedAdapters, at time.Time) (HostGenerationFenceReceipt, error) {
	started := time.Now()
	fail := func() (HostGenerationFenceReceipt, error) { return HostGenerationFenceReceipt{}, ErrWitnessUnavailable }
	if ctx == nil || ctx.Err() != nil || at.IsZero() || !q.sourceQualified || !witnessDigest.MatchString(q.adminRootDigest) || b.QualificationDigest != q.qualificationDigest || !at.Before(q.qualificationExpiry) {
		return fail()
	}
	for _, s := range []string{b.ReplacementID, b.ControllerInstanceID, b.OldHostID, b.NewHostID, b.PlanID, b.RunID, b.StepID, b.LeaseID, b.Nonce, b.ReceiptID} {
		if !validWitnessToken(s) {
			return fail()
		}
	}
	for _, s := range []string{b.OldIdentityDigest, b.NewIdentityDigest, b.FrozenAliasesDigest, b.AuthorityDigest, b.PlanDigest, b.RequirementsDigest, b.QualificationDigest} {
		if !witnessDigest.MatchString(s) {
			return fail()
		}
	}
	if b.OldHostID == b.NewHostID || b.OldIdentityDigest == b.NewIdentityDigest || b.RecoveryEpoch < 0 || b.PriorGeneration < 1 || b.NextGeneration != b.PriorGeneration+1 || b.IssuedAt.IsZero() || b.IssuedAt.After(at) || !at.Before(b.Deadline) || b.Deadline.Sub(b.IssuedAt) > maxWitnessAge || b.Deadline.After(q.qualificationExpiry) {
		return fail()
	}
	digest, e := HostGenerationRequirementsDigest(required)
	if e != nil || digest != b.RequirementsDigest {
		return fail()
	}
	ctx, cancel := context.WithTimeout(ctx, b.Deadline.Sub(at))
	defer cancel()
	receipt := HostGenerationFenceReceipt{Binding: b, ChallengeID: HostGenerationChallengeID(b), ExpiresAt: b.Deadline}
	for _, r := range required {
		probe, ok := q.entries[r.AdapterID].(hostGenerationProber)
		if !ok {
			return fail()
		}
		challenge := recoverydenial.Challenge{ChallengeID: receipt.ChallengeID, Kind: r.Kind, SubjectID: r.SubjectID, TargetID: r.TargetID, AdapterID: r.AdapterID, FormerIdentityID: r.FormerIdentityID, ProbeID: r.ProbeID, Deadline: b.Deadline}
		result, err := probe.probeHostGeneration(ctx, challenge)
		if err != nil || recoverydenial.ValidateResult(ctx, challenge, result, at.Add(time.Since(started))) != nil || result.ObserverID == b.ControllerInstanceID || result.ObserverID == b.OldHostID || result.ObserverID == b.NewHostID || result.ObserverID == b.OldIdentityDigest || result.ObserverID == b.NewIdentityDigest || result.ObservedAt.Before(b.IssuedAt) {
			return fail()
		}
		receipt.Transcripts = append(receipt.Transcripts, DirectDenialTranscript{Requirement: r, ObserverID: result.ObserverID, ChallengeID: result.ChallengeID, ResponseClass: result.ResponseClass, ResponseDigest: result.ResponseDigest, ObservedAt: result.ObservedAt, ExpiresAt: result.ExpiresAt, SessionExpiry: result.SessionExpiry, Denied: result.Denied})
		for _, expiry := range []time.Time{result.ExpiresAt, result.SessionExpiry, result.ObservedAt.Add(maxWitnessAge)} {
			if expiry.Before(receipt.ExpiresAt) {
				receipt.ExpiresAt = expiry
			}
		}
	}
	if ctx.Err() != nil || !at.Add(time.Since(started)).Before(receipt.ExpiresAt) {
		return fail()
	}
	receipt.Digest = fenceDigest(receipt)
	return receipt, nil
}

func (v qualifiedGroupVerifier) probeHostGeneration(ctx context.Context, c recoverydenial.Challenge) (recoverydenial.Result, error) {
	r := BoundaryRequirement{Kind: c.Kind, SubjectID: c.SubjectID, TargetID: c.TargetID, AdapterID: c.AdapterID, FormerIdentityID: c.FormerIdentityID, ProbeID: c.ProbeID}
	p, ok := v.groups[requirementQualificationKey(r)].(hostGenerationProber)
	if !ok {
		return recoverydenial.Result{}, ErrWitnessUnavailable
	}
	return p.probeHostGeneration(ctx, c)
}

// HostGenerationQualification reports only an already sealed, current registry.
func HostGenerationQualification(q QualifiedAdapters, at time.Time) (string, time.Time, error) {
	if at.IsZero() || !q.sourceQualified || !witnessDigest.MatchString(q.qualificationDigest) || !witnessDigest.MatchString(q.adminRootDigest) || !at.Before(q.qualificationExpiry) {
		return "", time.Time{}, ErrWitnessUnavailable
	}
	return q.qualificationDigest, q.qualificationExpiry, nil
}

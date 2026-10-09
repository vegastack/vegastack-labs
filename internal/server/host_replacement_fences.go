package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/vegastack/vegastack-labs/internal/debianaccess"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"github.com/vegastack/vegastack-labs/internal/recovery"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// The qualified file decides whether an installed verifier can prove each
// boundary, never which boundaries exist. Applicability comes from the store.
// For control replacement this is an additional post-restore alias fence; it
// cannot replace the existing control restore witness, custody or canary.
func replacementFenceRequirements(s store.HostReplacementFenceScope) ([]recovery.BoundaryRequirement, error) {
	if s.State.Status != "frozen" || (s.Request.RestorationClass != "stateless-role" && s.Request.RestorationClass != "control-database") || len(s.Outstanding) != 0 || s.Request.OldHostID == "" || s.Request.NewHostID == "" || debianaccess.ProtectedName(s.Request.NewHostID) || s.AuthorityDigest == "" || len(s.Credentials) > 62 {
		return nil, recovery.ErrWitnessUnavailable
	}
	out := []recovery.BoundaryRequirement{}
	add := func(kind, subject, target, former string, probes ...string) error {
		for _, v := range []string{subject, target, former} {
			if debianaccess.ProtectedName(v) {
				return recovery.ErrWitnessUnavailable
			}
		}
		for _, probe := range probes {
			out = append(out, recovery.BoundaryRequirement{Kind: kind, SubjectID: subject, TargetID: target, FormerIdentityID: former, AdapterID: "https-direct-denial-v1", ProbeID: probe})
		}
		return nil
	}
	if e := add("host-service", s.Request.OldHostID, s.Request.OldHostID, s.Request.OldIdentityDigest, "service-denied", "alternate-process-denied"); e != nil {
		return nil, e
	}

	for _, c := range s.Credentials {
		if c.ReferenceID == "" || c.MaterialVersion == "" || c.ResolverID != "native-systemd" || !((c.ConsumerID == hostaction.AdapterID && c.PurposeID == hostaction.PurposeID) || (c.ConsumerID == hostdiscovery.Consumer && c.PurposeID == hostdiscovery.Purpose)) {
			return nil, recovery.ErrWitnessUnavailable
		}
		identity := hostaction.Digest(struct{ ReferenceID, MaterialVersion string }{c.ReferenceID, c.MaterialVersion})
		if e := add("ssh", c.ReferenceID, c.TargetID, identity, "new-auth-denied", "open-session-denied"); e != nil {
			return nil, e
		}
		if e := add("secret-resolver", c.ReferenceID, c.TargetID, identity, "resolve-denied", "cached-material-denied"); e != nil {
			return nil, e
		}
	}
	if _, e := recovery.HostGenerationRequirementsDigest(out); e != nil {
		return nil, e
	}
	return out, nil
}

func verifyReplacementFences(ctx context.Context, repo *store.HostReplacementRepository, x store.HostReplacementExecution, at time.Time) (recovery.HostGenerationFenceReceipt, error) {
	if repo == nil || ctx == nil || ctx.Err() != nil || at.IsZero() {
		return recovery.HostGenerationFenceReceipt{}, recovery.ErrWitnessUnavailable
	}
	started := time.Now()
	scope, err := repo.CurrentHostReplacementFenceScope(ctx, x)
	if err != nil {
		return recovery.HostGenerationFenceReceipt{}, err
	}
	required, err := replacementFenceRequirements(scope)
	if err != nil {
		return recovery.HostGenerationFenceReceipt{}, err
	}
	qualified, err := recovery.LoadSystemQualifiedAdapters(ctx, required, at)
	if err != nil {
		return recovery.HostGenerationFenceReceipt{}, err
	}
	return verifyReplacementFencesWithQualified(ctx, repo, x, at.Add(time.Since(started)), qualified)
}

// This private seam accepts only the sealed registry capability. It exposes no
// loader, factory, endpoint or unchecked verifier injection. The production
// entry point above always loads protected system qualification itself.
func verifyReplacementFencesWithQualified(ctx context.Context, repo *store.HostReplacementRepository, x store.HostReplacementExecution, at time.Time, qualified recovery.QualifiedAdapters) (recovery.HostGenerationFenceReceipt, error) {
	if repo == nil || ctx == nil || ctx.Err() != nil || at.IsZero() {
		return recovery.HostGenerationFenceReceipt{}, recovery.ErrWitnessUnavailable
	}
	started := time.Now()
	qualification, expiry, err := recovery.HostGenerationQualification(qualified, at)
	if err != nil {
		return recovery.HostGenerationFenceReceipt{}, err
	}
	scope, err := repo.CurrentHostReplacementFenceScope(ctx, x)
	if err != nil {
		return recovery.HostGenerationFenceReceipt{}, err
	}
	required, err := replacementFenceRequirements(scope)
	if err != nil {
		return recovery.HostGenerationFenceReceipt{}, err
	}
	nonce := make([]byte, 32)
	if _, err = rand.Read(nonce); err != nil {
		return recovery.HostGenerationFenceReceipt{}, err
	}
	deadline := at.Add(60 * time.Second)
	if expiry.Before(deadline) {
		deadline = expiry
	}
	requirementsDigest, _ := recovery.HostGenerationRequirementsDigest(required)
	b := recovery.HostGenerationFenceBinding{ReplacementID: x.ReplacementID, ControllerInstanceID: scope.ControllerInstanceID, OldHostID: scope.Request.OldHostID, NewHostID: scope.Request.NewHostID, OldIdentityDigest: scope.Request.OldIdentityDigest, NewIdentityDigest: scope.Request.NewIdentityDigest, FrozenAliasesDigest: hostaction.Digest(scope.State.AliasBindings), AuthorityDigest: scope.AuthorityDigest, PlanID: x.PlanID, PlanDigest: x.PlanDigest, RunID: x.RunID, StepID: x.StepID, LeaseID: x.LeaseID, RequirementsDigest: requirementsDigest, QualificationDigest: qualification, Nonce: hex.EncodeToString(nonce), ReceiptID: "replacement-fence/" + hex.EncodeToString(nonce[:16]), RecoveryEpoch: scope.RecoveryEpoch, PriorGeneration: scope.State.PriorOwnershipGeneration, NextGeneration: scope.State.ProposedOwnershipGeneration, IssuedAt: at, Deadline: deadline}
	raw, err := json.Marshal(b)
	if err != nil {
		return recovery.HostGenerationFenceReceipt{}, err
	}
	if err = repo.PersistFenceChallenge(ctx, x, raw); err != nil {
		return recovery.HostGenerationFenceReceipt{}, err
	}

	receipt, err := recovery.VerifyHostGenerationFences(ctx, b, required, qualified, at.Add(time.Since(started)))
	if err != nil {
		return recovery.HostGenerationFenceReceipt{}, err
	}
	raw, err = json.Marshal(receipt)
	if err != nil {
		return recovery.HostGenerationFenceReceipt{}, err
	}
	if err = repo.RecordFenceReceipt(ctx, x, raw); err != nil {
		return recovery.HostGenerationFenceReceipt{}, err
	}
	return receipt, nil
}

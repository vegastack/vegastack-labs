package server

import (
	"context"
	"slices"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/adapter/localbackup"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

const recoveryBackupCredentialCapability = "credential.backup.read"

type recoveryCredentialReferences interface {
	GetActiveVersion(context.Context, string, int64) (generated.CredentialReference, error)
}

type recoveryCredentialProfiles interface {
	GetAppliedProfileScope(context.Context) (store.GateAppliedProfile, error)
}

type recoveryCanaryCredentialProfiles interface {
	GetAppliedRecoveryProfileScope(context.Context) (store.GateAppliedProfile, error)
}

type recoveryCredentialRevisions interface {
	CurrentRevision(context.Context) (store.RevisionToken, error)
}

type recoveryCredentialResolvers interface {
	ResolveCredentialCapability(string, string, string) (string, error)
	ResolveCredentialResolver(string, string, string) (adapter.CredentialResolver, error)
}

// recoveryCredentialBorrower reuses the current credential-reference and
// applied-capability boundaries for restore reads. It does not accept a
// caller-supplied resolver, material version, target, or purpose and returns
// only a borrowed value that the recovery adapter must close.
type recoveryCredentialBorrower struct {
	references recoveryCredentialReferences
	profiles   recoveryCredentialProfiles
	revisions  recoveryCredentialRevisions
	resolvers  recoveryCredentialResolvers
}

func (borrower recoveryCredentialBorrower) BorrowRecoveryCredential(ctx context.Context, request localbackup.RecoveryCredentialRequest) (*credentialref.Value, error) {
	blocked := func() (*credentialref.Value, error) {
		return nil, failure.New(generated.ErrorCodePrerequisiteBlocked, "restore-local-credential", false)
	}
	if ctx == nil || ctx.Err() != nil || borrower.references == nil || borrower.profiles == nil || borrower.revisions == nil || borrower.resolvers == nil ||
		request.ReferenceID == "" || request.ConsumerID != localbackup.AdapterID || request.PlanID == "" || len(request.PlanDigest) != 71 || !strings.HasPrefix(request.PlanDigest, "sha256:") ||
		request.RunID == "" || request.StepID == "" || request.LeaseID == "" || request.StateRevision <= 0 || request.RecoveryEpoch < 0 {
		return blocked()
	}
	for _, id := range []string{request.ReferenceID, request.ConsumerID, request.PlanID, request.RunID, request.StepID, request.LeaseID} {
		if _, err := credentialref.ParseID(id); err != nil {
			return blocked()
		}
	}
	current, err := borrower.revisions.CurrentRevision(ctx)
	if err != nil || current != (store.RevisionToken{StateRevision: request.StateRevision, RecoveryEpoch: request.RecoveryEpoch}) {
		return blocked()
	}
	profile, err := borrower.profiles.GetAppliedProfileScope(ctx)
	if err != nil || profile.ProfileID == "" || profile.RecoveryEpoch != request.RecoveryEpoch || profile.StateRevision > request.StateRevision {
		return blocked()
	}
	reference, err := borrower.references.GetActiveVersion(ctx, request.ReferenceID, request.RecoveryEpoch)
	if err != nil || reference.ReferenceID != request.ReferenceID || reference.ConsumerID != request.ConsumerID || reference.Status != "active" || reference.ActivatedAt == nil || reference.StateRevision > request.StateRevision || !slices.Contains(reference.VerifiedConsumerIDs, request.ConsumerID) {
		return blocked()
	}
	capability, err := borrower.resolvers.ResolveCredentialCapability(reference.ResolverID, request.ConsumerID, profile.ProfileID)
	if err != nil || capability == "" || !slices.Contains(profile.Capabilities, capability) {
		return blocked()
	}
	resolver, err := borrower.resolvers.ResolveCredentialResolver(reference.ResolverID, request.ConsumerID, profile.ProfileID)
	if err != nil || resolver == nil {
		return blocked()
	}
	binding := credentialref.StepBinding{OperationID: request.StepID, AdapterID: request.ConsumerID, TargetID: reference.TargetID, ReferenceID: reference.ReferenceID, ConsumerID: reference.ConsumerID, PurposeID: reference.PurposeID, MaterialVersion: reference.MaterialVersion, ResolverID: reference.ResolverID, StateRevision: request.StateRevision, RecoveryEpoch: request.RecoveryEpoch}
	if !credentialref.ValidBinding(binding) {
		return blocked()
	}
	value, err := resolver.Resolve(ctx, binding)
	if err != nil || value == nil || len(value.Bytes()) == 0 {
		if value != nil {
			value.Close()
		}
		return blocked()
	}
	return value, nil
}

// BorrowRecoveryCanaryCredential reacquires the source epoch's exact active
// backup key only while the store is at the immediately following
// recovery-required epoch. The resolver receives the historical reference
// epoch, so its own protected-file binding still validates the same version.
func (borrower recoveryCredentialBorrower) BorrowRecoveryCanaryCredential(ctx context.Context, request localbackup.RecoveryCredentialRequest, priorEpoch int64) (*credentialref.Value, error) {
	blocked := func() (*credentialref.Value, error) {
		return nil, failure.New(generated.ErrorCodePrerequisiteBlocked, "recovery-canary-credential", false)
	}
	profiles, ok := borrower.profiles.(recoveryCanaryCredentialProfiles)
	if !ok || priorEpoch < 0 || request.RecoveryEpoch != priorEpoch+1 || borrower.references == nil || borrower.revisions == nil || borrower.resolvers == nil {
		return blocked()
	}
	current, err := borrower.revisions.CurrentRevision(ctx)
	if err != nil || current != (store.RevisionToken{StateRevision: request.StateRevision, RecoveryEpoch: request.RecoveryEpoch}) {
		return blocked()
	}
	profile, err := profiles.GetAppliedRecoveryProfileScope(ctx)
	if err != nil || profile.RecoveryEpoch != priorEpoch || !slices.Contains(profile.Capabilities, recoveryBackupCredentialCapability) {
		return blocked()
	}
	reference, err := borrower.references.GetActiveVersion(ctx, request.ReferenceID, priorEpoch)
	if err != nil || reference.ReferenceID != request.ReferenceID || reference.ConsumerID != request.ConsumerID || reference.Status != "active" || reference.ActivatedAt == nil || !slices.Contains(reference.VerifiedConsumerIDs, request.ConsumerID) {
		return blocked()
	}
	capability, err := borrower.resolvers.ResolveCredentialCapability(reference.ResolverID, request.ConsumerID, profile.ProfileID)
	if err != nil || capability != recoveryBackupCredentialCapability {
		return blocked()
	}
	resolver, err := borrower.resolvers.ResolveCredentialResolver(reference.ResolverID, request.ConsumerID, profile.ProfileID)
	if err != nil || resolver == nil {
		return blocked()
	}
	binding := credentialref.StepBinding{OperationID: request.StepID, AdapterID: request.ConsumerID, TargetID: reference.TargetID, ReferenceID: reference.ReferenceID, ConsumerID: reference.ConsumerID, PurposeID: reference.PurposeID, MaterialVersion: reference.MaterialVersion, ResolverID: reference.ResolverID, StateRevision: request.StateRevision, RecoveryEpoch: priorEpoch}
	if !credentialref.ValidBinding(binding) {
		return blocked()
	}
	value, err := resolver.Resolve(ctx, binding)
	if err != nil || value == nil || len(value.Bytes()) == 0 {
		if value != nil {
			value.Close()
		}
		return blocked()
	}
	return value, nil
}

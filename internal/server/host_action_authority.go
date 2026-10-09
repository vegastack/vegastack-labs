package server

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/store"
	"time"
)

type ActionSigner interface {
	Sign(context.Context, []byte) ([]byte, error)
	KeyID() string
	PublicKey() ed25519.PublicKey
}
type hostActionExecutionSource interface {
	CurrentExecution(context.Context, adapter.Operation, adapter.ExactExecutionBinding) (store.HostActionExecution, error)
}
type HostActionAuthority struct {
	repository hostActionExecutionSource
	signer     ActionSigner
	now        func() time.Time
}

func actionFailure() error {
	return failure.New(generated.ErrorCodeAuthorizationDenied, "host-action", false)
}
func NewHostActionAuthority(repository *store.HostActionRepository, signer ActionSigner, now func() time.Time) (*HostActionAuthority, error) {
	if repository == nil || signer == nil || now == nil || len(signer.PublicKey()) != ed25519.PublicKeySize || signer.KeyID() == "" {
		return nil, actionFailure()
	}
	return &HostActionAuthority{repository: repository, signer: signer, now: now}, nil
}

type HostActionBundleIssuer struct {
	Repository hostActionExecutionSource
	Signer     ActionSigner
	Clock      func() time.Time
}

func bundleFromExecution(x store.HostActionExecution, issued, expires time.Time) generated.HostActionBundle {
	r := x.Draft.Request
	p := x.Plan
	l := x.Lease
	return generated.HostActionBundle{Schema: generated.SchemaIDHostActionBundle, SchemaVersion: "1.0.0", ActionID: r.ActionID, ActionVersion: r.ActionVersion, ActionInput: r.ActionInput, ActionInputDigest: r.ActionInputDigest, BundleID: "action-" + hostaction.Digest([]string{p.PlanID, p.PlanDigest, r.HostID, x.Draft.Digest})[7:39], PlanID: p.PlanID, PlanDigest: p.PlanDigest, RunID: x.Run.RunID, StepID: x.Step.StepID, LeaseID: l.LeaseID, HostID: r.HostID, HostIdentityDigest: r.ConsoleConfirmation.HostIdentityDigest, DeclarationID: p.DeclarationID, DeclarationRevision: p.Binding.DeclarationRevision, StateRevision: p.Binding.StateRevision, RecoveryEpoch: p.Binding.RecoveryEpoch, AutomationPrincipalID: r.AutomationPrincipalID, CallerUID: r.CallerUID, CredentialReferenceID: r.CredentialReferenceID, CredentialMaterialVersion: r.CredentialMaterialVersion, ConsoleConfirmationDigest: hostaction.Digest(r.ConsoleConfirmation), IssuedAt: issued.UTC().Format(time.RFC3339), ExpiresAt: expires.UTC().Format(time.RFC3339)}
}
func actionDeadline(x store.HostActionExecution, now time.Time) (time.Time, error) {
	deadline := now.Add(5 * time.Minute)
	for _, value := range []string{x.Plan.ExpiresAt, x.Lease.LeaseExpiresAt, x.Lease.MaximumExpiresAt} {
		at, err := time.Parse(time.RFC3339, value)
		if err != nil || !now.Before(at) {
			return time.Time{}, actionFailure()
		}
		if at.Before(deadline) {
			deadline = at
		}
	}
	return deadline, nil
}
func (i *HostActionBundleIssuer) Issue(ctx context.Context, op adapter.Operation, b adapter.ExactExecutionBinding) (generated.HostActionEnvelope, error) {
	if i == nil || i.Repository == nil || i.Signer == nil || i.Clock == nil {
		return generated.HostActionEnvelope{}, actionFailure()
	}
	x, err := i.Repository.CurrentExecution(ctx, op, b)
	if err != nil {
		return generated.HostActionEnvelope{}, err
	}
	now := i.Clock().UTC().Truncate(time.Second)
	expiry, err := actionDeadline(x, now)
	if err != nil {
		return generated.HostActionEnvelope{}, err
	}
	bundle := bundleFromExecution(x, now, expiry)
	message, err := hostaction.EnvelopeMessage(bundle, i.Signer.KeyID())
	if err != nil {
		return generated.HostActionEnvelope{}, err
	}
	signature, err := i.Signer.Sign(ctx, message)
	if err != nil {
		return generated.HostActionEnvelope{}, actionFailure()
	}
	e := generated.HostActionEnvelope{Schema: generated.SchemaIDHostActionEnvelope, SchemaVersion: "1.0.0", Bundle: bundle, KeyID: i.Signer.KeyID(), Signature: base64.StdEncoding.EncodeToString(signature)}
	raw, _ := json.Marshal(e)
	if _, err = hostaction.VerifyEnvelope(raw, hostaction.Policy{HostID: bundle.HostID, HostIdentityDigest: bundle.HostIdentityDigest, CallerUID: uint32(bundle.CallerUID), KeyID: e.KeyID, PublicKey: i.Signer.PublicKey()}, now); err != nil {
		return generated.HostActionEnvelope{}, err
	}
	return e, nil
}
func (a *HostActionAuthority) Authorize(ctx context.Context, envelope generated.HostActionEnvelope, c generated.HostActionChallenge) (generated.HostActionAuthorization, error) {
	var out generated.HostActionAuthorization
	if a == nil || a.repository == nil || a.signer == nil || a.now == nil {
		return out, actionFailure()
	}
	now := a.now().UTC().Truncate(time.Second)
	b := envelope.Bundle
	raw, _ := json.Marshal(envelope)
	if _, err := hostaction.VerifyEnvelope(raw, hostaction.Policy{HostID: b.HostID, HostIdentityDigest: b.HostIdentityDigest, CallerUID: uint32(b.CallerUID), KeyID: a.signer.KeyID(), PublicKey: a.signer.PublicKey()}, now); err != nil {
		return out, err
	}
	// Reload the operation from the immutable plan via its persisted binding;
	// the exact source resolves missing transport metadata, never caller fields.
	resolver, ok := a.repository.(interface {
		ExecutionForBundle(context.Context, generated.HostActionBundle) (store.HostActionExecution, error)
	})
	if !ok {
		return out, actionFailure()
	}
	x, err := resolver.ExecutionForBundle(ctx, b)
	if err != nil {
		return out, err
	}
	issued, e1 := time.Parse(time.RFC3339, b.IssuedAt)
	expiry, e2 := time.Parse(time.RFC3339, b.ExpiresAt)
	limit, e3 := actionDeadline(x, now)
	if e1 != nil || e2 != nil || e3 != nil || expiry.After(limit) || bundleFromExecution(x, issued, expiry) != b {
		return out, actionFailure()
	}
	digest, _ := hostaction.BundleDigest(b)
	nonce, e4 := base64.StdEncoding.Strict().DecodeString(c.Nonce)
	started, e5 := time.Parse(time.RFC3339, c.StartedAt)
	if e4 != nil || len(nonce) != 32 || e5 != nil || started.After(now) || now.Sub(started) >= hostaction.AuthorizationWindow || c.HostID != b.HostID || c.BundleDigest != digest {
		return out, actionFailure()
	}
	expires := now.Add(hostaction.AuthorizationWindow)
	if expiry.Before(expires) {
		expires = expiry
	}
	if started.Add(hostaction.AuthorizationWindow).Before(expires) {
		expires = started.Add(hostaction.AuthorizationWindow)
	}
	out = generated.HostActionAuthorization{Schema: generated.SchemaIDHostActionAuthorization, SchemaVersion: "1.0.0", BundleDigest: digest, ChallengeDigest: hostaction.Digest(c), KeyID: a.signer.KeyID(), AuthorizedAt: now.Format(time.RFC3339), ExpiresAt: expires.Format(time.RFC3339), StateRevision: b.StateRevision, RecoveryEpoch: b.RecoveryEpoch}
	signature, err := a.signer.Sign(ctx, hostaction.AuthorizationMessage(out))
	if err != nil {
		return generated.HostActionAuthorization{}, actionFailure()
	}
	out.Signature = base64.StdEncoding.EncodeToString(signature)
	return out, nil
}

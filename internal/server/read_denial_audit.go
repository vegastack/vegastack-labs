package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type readDenialAuditStore interface {
	Health(context.Context) (store.Health, error)
	AppendOperationalAudit(context.Context, store.OperationalAuditRequest) (store.OperationalAuditResult, error)
}

type auditingReadAuthorizer struct {
	next        authorization.ReadAuthorizer
	audits      readDenialAuditStore
	nonceSource io.Reader
}

func newAuditingReadAuthorizer(next authorization.ReadAuthorizer, audits readDenialAuditStore) authorization.ReadAuthorizer {
	return &auditingReadAuthorizer{next: next, audits: audits, nonceSource: rand.Reader}
}

func (authorizer *auditingReadAuthorizer) AuthorizeRead(ctx context.Context, principal identity.Principal, target authorization.ReadTarget) (authorization.ReadScope, error) {
	if authorizer == nil || authorizer.next == nil || authorizer.audits == nil || authorizer.nonceSource == nil {
		return authorization.ReadScope{}, failure.New(generated.ErrorCodeIntegrityFailure, "read-denial-audit", false)
	}
	scope, err := authorizer.next.AuthorizeRead(ctx, principal, target)
	if err == nil || stableCode(err) != generated.ErrorCodeAuthorizationDenied {
		return scope, err
	}
	if auditErr := authorizer.record(ctx, principal, target); auditErr != nil {
		return authorization.ReadScope{}, failure.New(generated.ErrorCodeIntegrityFailure, "read-denial-audit", false)
	}
	return authorization.ReadScope{}, err
}

func stableCode(err error) string {
	if code := store.Code(err); code != "" {
		return code
	}
	if stable, ok := failure.As(err); ok {
		return stable.Code
	}
	return ""
}

func (authorizer *auditingReadAuthorizer) record(ctx context.Context, principal identity.Principal, target authorization.ReadTarget) error {
	nonce := make([]byte, 16)
	if _, err := io.ReadFull(authorizer.nonceSource, nonce); err != nil {
		return err
	}
	attribution, err := audit.NewAttribution(principal, &principal, nil)
	if err != nil {
		return err
	}
	targetFingerprint := readDenialFingerprint("target", target.Capability, target.ResourceKind, target.ResourceID)
	requestFingerprint := readDenialFingerprint("request", targetFingerprint, hex.EncodeToString(nonce))
	after := audit.Fingerprint(readDenialFingerprint("result", generated.ErrorCodeAuthorizationDenied))
	request := store.OperationalAuditRequest{
		Idempotency: audit.IntentKey{Scope: "read-authorization-denial", KeyDigest: audit.Fingerprint(requestFingerprint), RequestDigest: audit.Fingerprint(requestFingerprint)},
		Event: audit.EventDraft{
			Type:          "authorization.read-denied",
			CorrelationID: "read-denial-" + hex.EncodeToString(nonce),
			Attribution:   attribution,
			Target:        audit.Target{Kind: "read-authorization", ID: targetFingerprint},
			After:         &after,
		},
	}
	for attempt := 0; attempt < 2; attempt++ {
		health, err := authorizer.audits.Health(ctx)
		if err != nil {
			return err
		}
		request.Expected = health.Revision
		if _, err = authorizer.audits.AppendOperationalAudit(ctx, request); err == nil || store.Code(err) != generated.ErrorCodeStateConflict {
			return err
		}
	}
	return failure.New(generated.ErrorCodeStateConflict, "read-denial-audit", false)
}

func readDenialFingerprint(parts ...string) string {
	digest := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "sha256:" + hex.EncodeToString(digest[:])
}

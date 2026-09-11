package server

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type readAuthorizerFunc func(context.Context, identity.Principal, authorization.ReadTarget) (authorization.ReadScope, error)

func (function readAuthorizerFunc) AuthorizeRead(ctx context.Context, principal identity.Principal, target authorization.ReadTarget) (authorization.ReadScope, error) {
	return function(ctx, principal, target)
}

type recordingReadDenialAuditor struct {
	request store.OperationalAuditRequest
	err     error
}

func (auditor *recordingReadDenialAuditor) Health(context.Context) (store.Health, error) {
	return store.Health{Revision: store.RevisionToken{StateRevision: 7, RecoveryEpoch: 2}}, nil
}

func (auditor *recordingReadDenialAuditor) AppendOperationalAudit(_ context.Context, request store.OperationalAuditRequest) (store.OperationalAuditResult, error) {
	auditor.request = request
	return store.OperationalAuditResult{}, auditor.err
}

func TestReadAuthorizationDenialAuditIsSanitizedAndFailClosed(t *testing.T) {
	denied := readAuthorizerFunc(func(context.Context, identity.Principal, authorization.ReadTarget) (authorization.ReadScope, error) {
		return authorization.ReadScope{}, failure.New(generated.ErrorCodeAuthorizationDenied, "read", false)
	})
	principal := identity.Principal{ID: "principal.remote", Method: identity.CloudflareAccessMethod}
	target := authorization.ReadTarget{Capability: "inventory.draft.read", ResourceKind: "inventory-draft", ResourceID: "private-target-canary"}
	auditor := &recordingReadDenialAuditor{}
	authorizer := &auditingReadAuthorizer{next: denied, audits: auditor, nonceSource: bytes.NewReader(make([]byte, 16))}
	if _, err := authorizer.AuthorizeRead(context.Background(), principal, target); stableCode(err) != generated.ErrorCodeAuthorizationDenied {
		t.Fatalf("denial = %v", err)
	}
	request := auditor.request
	if request.Event.Type != "authorization.read-denied" || request.Event.Attribution.AuthenticatedPrincipalID != principal.ID || !strings.HasPrefix(request.Event.Target.ID, "sha256:") || strings.Contains(request.Event.Target.ID, target.ResourceID) || request.Expected.StateRevision != 7 {
		t.Fatalf("unsafe audit request = %#v", request)
	}

	auditor.err = failure.New(generated.ErrorCodeIntegrityFailure, "audit", false)
	authorizer.nonceSource = bytes.NewReader(make([]byte, 16))
	if _, err := authorizer.AuthorizeRead(context.Background(), principal, target); stableCode(err) != generated.ErrorCodeIntegrityFailure {
		t.Fatalf("audit failure = %v", err)
	}
}

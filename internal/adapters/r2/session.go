// Package r2 contains the optional VegaStack Labs R2 deployment-profile
// adapter. Portable backup code depends only on adapter.SessionIssuer.
package r2

import (
	"context"
	"errors"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
)

// Pinned restic reads repository metadata and payload, creates new immutable
// objects, and removes its mutable locks. Retention rules, not session scope,
// deny overwrite/delete of the generation's protected prefixes.
var allowedWriterActions = []string{"DeleteObject", "GetObject", "ListBucket", "PutObject"}

// TemporaryCredentialSigner is the narrow local-signing seam. The parent is a
// borrowed value and may not be retained by an implementation.
type TemporaryCredentialSigner interface {
	SignScopedSession(context.Context, []byte, adapter.SessionRequest) (adapter.ScopedS3Session, error)
}

type SessionIssuer struct {
	Signer                               TemporaryCredentialSigner
	Clock                                func() time.Time
	ParentReferenceID, ParentFingerprint string
}

func (issuer SessionIssuer) Issue(ctx context.Context, request adapter.SessionRequest, parent *credentialref.Value) (adapter.ScopedS3Session, error) {
	invalid := errors.New("r2 scoped session denied")
	clock := issuer.Clock
	if clock == nil {
		clock = time.Now
	}
	actions := append([]string(nil), request.Actions...)
	slices.Sort(actions)
	cleanPrefix := strings.TrimSuffix(request.Prefix, "/")
	if issuer.Signer == nil || parent == nil || len(parent.Bytes()) == 0 ||
		request.ParentReferenceID != issuer.ParentReferenceID || request.ParentFingerprint != issuer.ParentFingerprint ||
		request.RunID == "" || request.StepID == "" || request.PointID == "" || request.GenerationID == "" || path.Clean(cleanPrefix) != cleanPrefix ||
		!strings.HasSuffix(cleanPrefix, "/"+request.GenerationID) || strings.Contains(cleanPrefix, "..") ||
		request.RecoveryEpoch < 0 || request.Prefix == "" || !slices.Equal(actions, allowedWriterActions) ||
		request.TTL <= 0 || request.TTL > 15*time.Minute || !clock().Before(request.Deadline) || clock().Add(request.TTL).After(request.Deadline) {
		return adapter.ScopedS3Session{}, invalid
	}
	session, err := issuer.Signer.SignScopedSession(ctx, parent.Bytes(), request)
	if err != nil {
		zeroSession(&session)
		return adapter.ScopedS3Session{}, err
	}
	if len(session.AccessKeyID) == 0 || len(session.SecretAccessKey) == 0 || len(session.SessionToken) == 0 ||
		session.ExpiresAt.After(request.Deadline) || session.ExpiresAt.After(clock().Add(request.TTL)) || !clock().Before(session.ExpiresAt) {
		zeroSession(&session)
		return adapter.ScopedS3Session{}, invalid
	}
	return session, nil
}

func zeroSession(session *adapter.ScopedS3Session) {
	for _, value := range [][]byte{session.AccessKeyID, session.SecretAccessKey, session.SessionToken} {
		for index := range value {
			value[index] = 0
		}
	}
	session.AccessKeyID, session.SecretAccessKey, session.SessionToken = nil, nil, nil
}

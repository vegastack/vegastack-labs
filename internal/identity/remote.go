package identity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/failure"
)

const (
	CloudflareAccessMethod = "cloudflare-access"
	SlackSocketModeMethod  = "slack-socket-mode"
)

const (
	maxIssuerBytes   = 2048
	maxSubjectBytes  = 512
	maxAudienceBytes = 512
	maxAudiences     = 16
)

// VerifiedIdentity is the provider-neutral result of cryptographically
// verifying one external identity assertion. It deliberately excludes email,
// display names, groups, raw claims, and provider tokens.
type VerifiedIdentity struct {
	Issuer    string
	Subject   string
	Audiences []string
	IssuedAt  time.Time
	ExpiresAt time.Time
	Method    string
}

// VerifiedIdentityAdapter validates one opaque provider assertion and returns
// only the bounded identity facts needed by the local binding store.
type VerifiedIdentityAdapter interface {
	Verify(context.Context, string) (VerifiedIdentity, error)
}

type remoteIdentityContextKey struct{}
type remoteIdentityContextValue struct{ identity VerifiedIdentity }

func WithVerifiedRemoteIdentity(ctx context.Context, value VerifiedIdentity) (context.Context, error) {
	if !validRemoteIdentity(value) {
		return ctx, failure.New("AUTHENTICATION_REQUIRED", "remote-identity", false)
	}
	value.Audiences = append([]string(nil), value.Audiences...)
	return context.WithValue(ctx, remoteIdentityContextKey{}, remoteIdentityContextValue{identity: value}), nil
}

func RemoteIdentityFromContext(ctx context.Context) (VerifiedIdentity, bool) {
	wrapped, ok := ctx.Value(remoteIdentityContextKey{}).(remoteIdentityContextValue)
	if !ok || !validRemoteIdentity(wrapped.identity) {
		return VerifiedIdentity{}, false
	}
	wrapped.identity.Audiences = append([]string(nil), wrapped.identity.Audiences...)
	return wrapped.identity, true
}

func BindingDigest(value VerifiedIdentity) (string, error) {
	if !validRemoteIdentity(value) {
		return "", failure.New("AUTHENTICATION_REQUIRED", "remote-identity", false)
	}
	audiences := append([]string(nil), value.Audiences...)
	sort.Strings(audiences)
	parts := []string{"remote-identity-v1", value.Method, value.Issuer, value.Subject}
	parts = append(parts, audiences...)
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func ValidPrincipal(principal Principal) bool {
	if !principalIDPattern.MatchString(principal.ID) || !ValidPrincipalKind(EffectivePrincipalKind(principal)) {
		return false
	}
	switch principal.Method {
	case LocalOSPeerMethod, CloudflareAccessMethod, SlackSocketModeMethod:
		return true
	default:
		return false
	}
}

func validRemoteIdentity(value VerifiedIdentity) bool {
	if value.Method != CloudflareAccessMethod || !boundedOpaque(value.Issuer, maxIssuerBytes) || !boundedOpaque(value.Subject, maxSubjectBytes) || len(value.Audiences) == 0 || len(value.Audiences) > maxAudiences || value.IssuedAt.IsZero() || !value.ExpiresAt.After(value.IssuedAt) {
		return false
	}
	seen := make(map[string]struct{}, len(value.Audiences))
	for _, audience := range value.Audiences {
		if !boundedOpaque(audience, maxAudienceBytes) {
			return false
		}
		if _, duplicate := seen[audience]; duplicate {
			return false
		}
		seen[audience] = struct{}{}
	}
	return true
}

func boundedOpaque(value string, maximum int) bool {
	if value == "" || len(value) > maximum || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character == 0x7f {
			return false
		}
	}
	return true
}

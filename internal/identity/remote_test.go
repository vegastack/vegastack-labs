package identity

import (
	"context"
	"testing"
	"time"
)

func TestBindingDigestValidatesAndCanonicalizesRemoteIdentity(t *testing.T) {
	now := time.Date(2026, 9, 10, 9, 0, 0, 0, time.UTC)
	base := VerifiedIdentity{
		Issuer:    "https://team.cloudflareaccess.com",
		Subject:   "opaque-subject",
		Audiences: []string{"aud-b", "aud-a"},
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
		Method:    CloudflareAccessMethod,
	}
	digest, err := BindingDigest(base)
	if err != nil {
		t.Fatal(err)
	}
	base.Audiences[0], base.Audiences[1] = base.Audiences[1], base.Audiences[0]
	second, err := BindingDigest(base)
	if err != nil || second != digest {
		t.Fatalf("canonical digest = (%q, %v), want %q", second, err, digest)
	}
	if len(digest) != len("sha256:")+64 {
		t.Fatalf("digest = %q", digest)
	}
}

func TestBindingDigestRejectsInvalidRemoteIdentity(t *testing.T) {
	now := time.Date(2026, 9, 10, 9, 0, 0, 0, time.UTC)
	tests := []VerifiedIdentity{
		{Subject: "subject", Audiences: []string{"aud"}, IssuedAt: now, ExpiresAt: now.Add(time.Hour), Method: CloudflareAccessMethod},
		{Issuer: "issuer", Audiences: []string{"aud"}, IssuedAt: now, ExpiresAt: now.Add(time.Hour), Method: CloudflareAccessMethod},
		{Issuer: "issuer", Subject: "subject", IssuedAt: now, ExpiresAt: now.Add(time.Hour), Method: CloudflareAccessMethod},
		{Issuer: "issuer", Subject: "subject", Audiences: []string{"aud", "aud"}, IssuedAt: now, ExpiresAt: now.Add(time.Hour), Method: CloudflareAccessMethod},
		{Issuer: "issuer", Subject: "subject", Audiences: []string{"aud"}, IssuedAt: now, ExpiresAt: now, Method: CloudflareAccessMethod},
		{Issuer: "issuer", Subject: "subject", Audiences: []string{"aud"}, IssuedAt: now, ExpiresAt: now.Add(time.Hour), Method: "forged"},
	}
	for _, value := range tests {
		if _, err := BindingDigest(value); err == nil {
			t.Fatalf("BindingDigest accepted %#v", value)
		}
	}
}

type remoteAdapterStub struct{}

func (remoteAdapterStub) Verify(context.Context, string) (VerifiedIdentity, error) {
	return VerifiedIdentity{}, nil
}

var _ VerifiedIdentityAdapter = remoteAdapterStub{}

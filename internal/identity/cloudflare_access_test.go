package identity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/vegastack/vegastack-labs/internal/failure"
)

type accessFixture struct {
	server    *httptest.Server
	key       *rsa.PrivateKey
	kid       string
	extraKeys []jose.JSONWebKey
	now       time.Time
	requests  atomic.Int64
	fail      atomic.Bool

	blockRequest   atomic.Int64
	refreshStarted chan struct{}
	releaseRefresh chan struct{}
}

func newAccessFixture(t *testing.T) *accessFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &accessFixture{key: key, kid: "key-current", now: time.Date(2026, 9, 10, 9, 0, 0, 0, time.UTC)}
	fixture.refreshStarted = make(chan struct{})
	fixture.releaseRefresh = make(chan struct{})
	fixture.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestNumber := fixture.requests.Add(1)
		if fixture.blockRequest.Load() == requestNumber {
			close(fixture.refreshStarted)
			<-fixture.releaseRefresh
		}
		if fixture.fail.Load() {
			http.Error(w, "provider detail that must remain private", http.StatusServiceUnavailable)
			return
		}
		keys := []jose.JSONWebKey{{Key: &fixture.key.PublicKey, KeyID: fixture.kid, Algorithm: string(jose.RS256), Use: "sig"}}
		keys = append(keys, fixture.extraKeys...)
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: keys})
	}))
	t.Cleanup(fixture.server.Close)
	return fixture
}

func (fixture *accessFixture) adapter(t *testing.T, clock func() time.Time) *CloudflareAccessAdapter {
	t.Helper()
	adapter, err := NewCloudflareAccessAdapter(CloudflareAccessConfig{
		Issuer: fixture.server.URL, Audience: "aud-console", CertificatesURL: fixture.server.URL,
		ClockSkew: time.Minute, MaxTokenBytes: 16 * 1024, KnownKeyOutageLimit: 24 * time.Hour,
	}, fixture.server.Client(), clock)
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

func (fixture *accessFixture) token(t *testing.T, key *rsa.PrivateKey, kid, issuer string, audience jwt.Audience, issuedAt, notBefore, expiry time.Time) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid))
	if err != nil {
		t.Fatal(err)
	}
	claims := jwt.Claims{Issuer: issuer, Subject: "opaque-subject", Audience: audience, IssuedAt: jwt.NewNumericDate(issuedAt), NotBefore: jwt.NewNumericDate(notBefore), Expiry: jwt.NewNumericDate(expiry)}
	privateClaims := map[string]any{}
	raw, err := os.ReadFile("testdata/cloudflare_access_claims.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &privateClaims); err != nil {
		t.Fatal(err)
	}
	token, err := jwt.Signed(signer).Claims(claims).Claims(privateClaims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestCloudflareAccessAdapterValidatesRS256AndRefreshesUnknownKey(t *testing.T) {
	fixture := newAccessFixture(t)
	now := fixture.now
	adapter := fixture.adapter(t, func() time.Time { return now })
	if err := adapter.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	token := fixture.token(t, fixture.key, fixture.kid, fixture.server.URL, jwt.Audience{"aud-console"}, now.Add(-time.Minute), now.Add(-time.Minute), now.Add(time.Hour))
	verified, err := adapter.Verify(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Subject != "opaque-subject" || verified.Issuer != fixture.server.URL || verified.Method != CloudflareAccessMethod || len(verified.Audiences) != 1 {
		t.Fatalf("verified = %#v", verified)
	}
	if encoded := strings.ToLower(verified.Subject + verified.Issuer + strings.Join(verified.Audiences, "")); strings.Contains(encoded, "private") || strings.Contains(encoded, "email") {
		t.Fatalf("private claim escaped: %#v", verified)
	}

	replacement, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fixture.key, fixture.kid = replacement, "key-rotated"
	rotated := fixture.token(t, replacement, fixture.kid, fixture.server.URL, jwt.Audience{"aud-console"}, now.Add(-time.Minute), now.Add(-time.Minute), now.Add(time.Hour))
	if _, err := adapter.Verify(context.Background(), rotated); err != nil {
		t.Fatalf("rotated key was not refreshed: %v", err)
	}
}

func TestCloudflareAccessAdapterCoalescesConcurrentUnknownKeyRefresh(t *testing.T) {
	for _, test := range []struct {
		name              string
		publishUnknownKey bool
		providerFails     bool
		wantCode          string
	}{
		{name: "rotated key becomes available", publishUnknownKey: true},
		{name: "key remains unknown", wantCode: "AUTHENTICATION_REQUIRED"},
		{name: "key provider fails", providerFails: true, wantCode: "AUTHENTICATION_REQUIRED"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newAccessFixture(t)
			now := fixture.now
			adapter := fixture.adapter(t, func() time.Time { return now })
			if err := adapter.Refresh(context.Background()); err != nil {
				t.Fatal(err)
			}

			unknownKey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			const unknownKID = "key-unknown-to-cache"
			token := fixture.token(t, unknownKey, unknownKID, fixture.server.URL, jwt.Audience{"aud-console"}, now.Add(-time.Minute), now.Add(-time.Minute), now.Add(time.Hour))
			if test.publishUnknownKey {
				fixture.key = unknownKey
				fixture.kid = unknownKID
			}
			fixture.fail.Store(test.providerFails)

			baselineRequests := fixture.requests.Load()
			fixture.blockRequest.Store(baselineRequests + 1)
			const workers = 8
			start := make(chan struct{})
			var ready sync.WaitGroup
			ready.Add(workers)
			results := make(chan error, workers)
			for range workers {
				go func() {
					<-start
					ready.Done()
					_, verifyErr := adapter.Verify(context.Background(), token)
					results <- verifyErr
				}()
			}
			close(start)
			ready.Wait()
			<-fixture.refreshStarted
			// Keep the first network refresh in flight long enough for every
			// verifier to queue behind the same observed cache generation.
			time.Sleep(25 * time.Millisecond)
			close(fixture.releaseRefresh)

			for range workers {
				if code := authCode(<-results); code != test.wantCode {
					t.Fatalf("verification code = %q, want %q", code, test.wantCode)
				}
			}
			if got := fixture.requests.Load() - baselineRequests; got != 1 {
				t.Fatalf("concurrent unknown key caused %d JWKS fetches, want 1", got)
			}
			if test.providerFails {
				fixture.fail.Store(false)
				fixture.key = unknownKey
				fixture.kid = unknownKID
				if _, err := adapter.Verify(context.Background(), token); err != nil {
					t.Fatalf("later request did not retry recovered provider: %v", err)
				}
				if got := fixture.requests.Load() - baselineRequests; got != 2 {
					t.Fatalf("recovery request count = %d, want 2", got)
				}
			}
		})
	}
}

func TestCloudflareAccessAdapterRejectsAdversarialTokens(t *testing.T) {
	fixture := newAccessFixture(t)
	now := fixture.now
	adapter := fixture.adapter(t, func() time.Time { return now })
	if err := adapter.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	tests := map[string]string{
		"unsigned":       "eyJhbGciOiJub25lIn0.eyJzdWIiOiJvcGFxdWUtc3ViamVjdCJ9.",
		"missing key id": signedAccessTokenWithoutKeyID(t, fixture.key, fixture.server.URL, now),
		"unknown key":    fixture.token(t, other, "unknown", fixture.server.URL, jwt.Audience{"aud-console"}, now.Add(-time.Minute), now.Add(-time.Minute), now.Add(time.Hour)),
		"wrong issuer":   fixture.token(t, fixture.key, fixture.kid, "https://wrong.example", jwt.Audience{"aud-console"}, now.Add(-time.Minute), now.Add(-time.Minute), now.Add(time.Hour)),
		"wrong audience": fixture.token(t, fixture.key, fixture.kid, fixture.server.URL, jwt.Audience{"aud-other"}, now.Add(-time.Minute), now.Add(-time.Minute), now.Add(time.Hour)),
		"expired":        fixture.token(t, fixture.key, fixture.kid, fixture.server.URL, jwt.Audience{"aud-console"}, now.Add(-time.Hour), now.Add(-time.Hour), now.Add(-2*time.Minute)),
		"not yet valid":  fixture.token(t, fixture.key, fixture.kid, fixture.server.URL, jwt.Audience{"aud-console"}, now, now.Add(2*time.Minute), now.Add(time.Hour)),
	}
	fixture.fail.Store(true)
	for name, token := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := adapter.Verify(context.Background(), token); authCode(err) != "AUTHENTICATION_REQUIRED" {
				t.Fatalf("error = %v", err)
			}
		})
	}
	if _, err := adapter.Verify(context.Background(), strings.Repeat("x", 16*1024+1)); authCode(err) != "AUTHENTICATION_REQUIRED" {
		t.Fatalf("oversized token error = %v", err)
	}
}

func TestCloudflareAccessAdapterAcceptsCurrentAndPreviousProviderKeys(t *testing.T) {
	fixture := newAccessFixture(t)
	previous, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fixture.extraKeys = []jose.JSONWebKey{{Key: &previous.PublicKey, KeyID: "key-previous", Algorithm: string(jose.RS256), Use: "sig"}}
	adapter := fixture.adapter(t, func() time.Time { return fixture.now })
	if err := adapter.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []struct {
		name string
		key  *rsa.PrivateKey
		kid  string
	}{{"current", fixture.key, fixture.kid}, {"previous", previous, "key-previous"}} {
		t.Run(candidate.name, func(t *testing.T) {
			token := fixture.token(t, candidate.key, candidate.kid, fixture.server.URL, jwt.Audience{"aud-console"}, fixture.now.Add(-time.Minute), fixture.now.Add(-time.Minute), fixture.now.Add(time.Hour))
			if _, err := adapter.Verify(context.Background(), token); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func signedAccessTokenWithoutKeyID(t *testing.T, key *rsa.PrivateKey, issuer string, now time.Time) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	token, err := jwt.Signed(signer).Claims(jwt.Claims{
		Issuer: issuer, Subject: "opaque-subject", Audience: jwt.Audience{"aud-console"},
		IssuedAt: jwt.NewNumericDate(now.Add(-time.Minute)), NotBefore: jwt.NewNumericDate(now.Add(-time.Minute)), Expiry: jwt.NewNumericDate(now.Add(time.Hour)),
	}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestCloudflareAccessAdapterRejectsWrongAlgorithm(t *testing.T) {
	fixture := newAccessFixture(t)
	adapter := fixture.adapter(t, func() time.Time { return fixture.now })
	if err := adapter.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte("01234567890123456789012345678901")}, (&jose.SignerOptions{}).WithHeader("kid", fixture.kid))
	if err != nil {
		t.Fatal(err)
	}
	token, err := jwt.Signed(signer).Claims(jwt.Claims{Issuer: fixture.server.URL, Subject: "opaque-subject", Audience: jwt.Audience{"aud-console"}, IssuedAt: jwt.NewNumericDate(fixture.now), Expiry: jwt.NewNumericDate(fixture.now.Add(time.Hour))}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Verify(context.Background(), token); authCode(err) != "AUTHENTICATION_REQUIRED" {
		t.Fatalf("HS256 error = %v", err)
	}
}

func TestCloudflareAccessAdapterBoundsKnownKeyOutage(t *testing.T) {
	fixture := newAccessFixture(t)
	now := fixture.now
	adapter := fixture.adapter(t, func() time.Time { return now })
	if err := adapter.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	token := fixture.token(t, fixture.key, fixture.kid, fixture.server.URL, jwt.Audience{"aud-console"}, now.Add(-time.Minute), now.Add(-time.Minute), now.Add(30*time.Hour))
	fixture.fail.Store(true)
	now = now.Add(23 * time.Hour)
	if _, err := adapter.Verify(context.Background(), token); err != nil {
		t.Fatalf("known 23-hour key rejected: %v", err)
	}
	now = fixture.now.Add(25 * time.Hour)
	if _, err := adapter.Verify(context.Background(), token); authCode(err) != "AUTHENTICATION_REQUIRED" {
		t.Fatalf("known 25-hour key error = %v", err)
	}
}

func TestCloudflareAccessAdapterRejectsRedirectAndOversizedJWKS(t *testing.T) {
	redirectTarget := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer redirectTarget.Close()
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTarget.URL, http.StatusFound)
	}))
	defer redirect.Close()
	adapter, err := NewCloudflareAccessAdapter(CloudflareAccessConfig{Issuer: redirect.URL, Audience: "aud", CertificatesURL: redirect.URL, KnownKeyOutageLimit: 24 * time.Hour}, redirect.Client(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.Refresh(context.Background()); authCode(err) != "AUTHENTICATION_REQUIRED" {
		t.Fatalf("redirect error = %v", err)
	}

	oversized := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", maxJWKSBytes+1)))
	}))
	defer oversized.Close()
	adapter, err = NewCloudflareAccessAdapter(CloudflareAccessConfig{Issuer: oversized.URL, Audience: "aud", CertificatesURL: oversized.URL, KnownKeyOutageLimit: 24 * time.Hour}, oversized.Client(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.Refresh(context.Background()); authCode(err) != "AUTHENTICATION_REQUIRED" {
		t.Fatalf("oversized JWKS error = %v", err)
	}
}

func TestCloudflareAccessConfigRejectsUnsafeEndpointsAndBounds(t *testing.T) {
	for _, config := range []CloudflareAccessConfig{
		{Issuer: "http://access.example", Audience: "aud", CertificatesURL: "http://access.example/certs"},
		{Issuer: "https://access.example", Audience: "aud", CertificatesURL: "https://other.example/certs"},
		{Issuer: "https://access.example", Audience: "aud", CertificatesURL: "https://user@access.example/certs"},
		{Issuer: "https://access.example", Audience: "aud", CertificatesURL: "https://access.example/certs", KnownKeyOutageLimit: 25 * time.Hour},
	} {
		if _, err := NewCloudflareAccessAdapter(config, http.DefaultClient, time.Now); err == nil {
			t.Fatalf("unsafe config accepted: %#v", config)
		}
	}
}

func authCode(err error) string {
	if stable, ok := failure.As(err); ok {
		return stable.Code
	}
	return ""
}

package identity

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/vegastack/vegastack-labs/internal/failure"
)

const (
	defaultMaxAccessTokenBytes = 16 * 1024
	maxJWKSBytes               = 256 * 1024
	maximumKnownKeyOutage      = 24 * time.Hour
	defaultHTTPTimeout         = 10 * time.Second
)

type CloudflareAccessConfig struct {
	Issuer              string
	Audience            string
	CertificatesURL     string
	ClockSkew           time.Duration
	MaxTokenBytes       int
	KnownKeyOutageLimit time.Duration
}

// CloudflareAccessAdapter verifies Access assertions while retaining only a
// bounded cache of public verification keys. Provider response bodies and JWT
// claims never escape this package.
type CloudflareAccessAdapter struct {
	config CloudflareAccessConfig
	client *http.Client
	clock  func() time.Time

	refreshMu         sync.Mutex
	cacheMu           sync.RWMutex
	keys              map[string]jose.JSONWebKey
	lastFetch         time.Time
	refreshGeneration uint64
	lastRefreshFailed bool
}

func NewCloudflareAccessAdapter(config CloudflareAccessConfig, client *http.Client, clock func() time.Time) (*CloudflareAccessAdapter, error) {
	config, err := validateCloudflareAccessConfig(config)
	if err != nil || client == nil || clock == nil {
		return nil, failure.New("INPUT_INVALID", "cloudflare-access-config", false)
	}
	configuredClient := *client
	if configuredClient.Timeout == 0 {
		configuredClient.Timeout = defaultHTTPTimeout
	}
	configuredClient.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("redirect denied") }
	return &CloudflareAccessAdapter{config: config, client: &configuredClient, clock: clock, keys: make(map[string]jose.JSONWebKey)}, nil
}

func validateCloudflareAccessConfig(config CloudflareAccessConfig) (CloudflareAccessConfig, error) {
	if config.MaxTokenBytes == 0 {
		config.MaxTokenBytes = defaultMaxAccessTokenBytes
	}
	if config.KnownKeyOutageLimit == 0 {
		config.KnownKeyOutageLimit = maximumKnownKeyOutage
	}
	issuer, issuerErr := url.Parse(config.Issuer)
	certificates, certificatesErr := url.Parse(config.CertificatesURL)
	if issuerErr != nil || certificatesErr != nil || !safeHTTPSURL(issuer) || !safeHTTPSURL(certificates) || !strings.EqualFold(issuer.Hostname(), certificates.Hostname()) || issuer.Port() != certificates.Port() || !boundedOpaque(config.Audience, maxAudienceBytes) || config.ClockSkew < 0 || config.ClockSkew > 5*time.Minute || config.MaxTokenBytes < 1024 || config.MaxTokenBytes > 64*1024 || config.KnownKeyOutageLimit <= 0 || config.KnownKeyOutageLimit > maximumKnownKeyOutage {
		return CloudflareAccessConfig{}, failure.New("INPUT_INVALID", "cloudflare-access-config", false)
	}
	return config, nil
}

func safeHTTPSURL(value *url.URL) bool {
	return value != nil && value.Scheme == "https" && value.Host != "" && value.Hostname() != "" && value.User == nil && value.RawQuery == "" && value.Fragment == ""
}

func (adapter *CloudflareAccessAdapter) Refresh(ctx context.Context) error {
	if adapter == nil {
		return authenticationFailure("remote-key-set")
	}
	adapter.refreshMu.Lock()
	defer adapter.refreshMu.Unlock()
	return adapter.refreshAndRecord(ctx)
}

func (adapter *CloudflareAccessAdapter) refreshIfGeneration(ctx context.Context, observed uint64) error {
	adapter.refreshMu.Lock()
	defer adapter.refreshMu.Unlock()

	adapter.cacheMu.RLock()
	current := adapter.refreshGeneration
	failed := adapter.lastRefreshFailed
	adapter.cacheMu.RUnlock()
	if current != observed {
		if failed {
			return authenticationFailure("remote-key-set")
		}
		return nil
	}
	return adapter.refreshAndRecord(ctx)
}

func (adapter *CloudflareAccessAdapter) refreshAndRecord(ctx context.Context) error {
	err := adapter.refresh(ctx)
	adapter.cacheMu.Lock()
	adapter.refreshGeneration++
	adapter.lastRefreshFailed = err != nil
	adapter.cacheMu.Unlock()
	return err
}

func (adapter *CloudflareAccessAdapter) refresh(ctx context.Context) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, adapter.config.CertificatesURL, nil)
	if err != nil {
		return authenticationFailure("remote-key-set")
	}
	request.Header.Set("Accept", "application/json")
	response, err := adapter.client.Do(request)
	if err != nil {
		return authenticationFailure("remote-key-set")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return authenticationFailure("remote-key-set")
	}
	limited := io.LimitReader(response.Body, maxJWKSBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil || len(body) == 0 || len(body) > maxJWKSBytes {
		return authenticationFailure("remote-key-set")
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(body, &set); err != nil || len(set.Keys) == 0 || len(set.Keys) > 32 {
		return authenticationFailure("remote-key-set")
	}
	keys := make(map[string]jose.JSONWebKey, len(set.Keys))
	for _, key := range set.Keys {
		publicKey, ok := key.Key.(*rsa.PublicKey)
		if !ok || publicKey.N == nil || publicKey.N.BitLen() < 2048 || key.KeyID == "" || len(key.KeyID) > 256 || key.Algorithm != string(jose.RS256) || (key.Use != "" && key.Use != "sig") || !key.Valid() {
			return authenticationFailure("remote-key-set")
		}
		if _, duplicate := keys[key.KeyID]; duplicate {
			return authenticationFailure("remote-key-set")
		}
		keys[key.KeyID] = key
	}
	adapter.cacheMu.Lock()
	adapter.keys = keys
	adapter.lastFetch = adapter.clock().UTC()
	adapter.cacheMu.Unlock()
	return nil
}

func (adapter *CloudflareAccessAdapter) Verify(ctx context.Context, assertion string) (VerifiedIdentity, error) {
	if adapter == nil || len(assertion) == 0 || len(assertion) > adapter.config.MaxTokenBytes || strings.TrimSpace(assertion) != assertion {
		return VerifiedIdentity{}, authenticationFailure("access-assertion")
	}
	signed, err := jose.ParseSigned(assertion, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil || len(signed.Signatures) != 1 {
		return VerifiedIdentity{}, authenticationFailure("access-assertion")
	}
	header := signed.Signatures[0].Header
	if header.Algorithm != string(jose.RS256) || header.KeyID == "" || len(header.KeyID) > 256 || header.JSONWebKey != nil {
		return VerifiedIdentity{}, authenticationFailure("access-assertion")
	}
	key, found, current, generation := adapter.cachedKey(header.KeyID)
	if !found || !current {
		if err := adapter.refreshIfGeneration(ctx, generation); err != nil {
			if !found || !current {
				return VerifiedIdentity{}, authenticationFailure("access-assertion")
			}
		}
		key, found, current, _ = adapter.cachedKey(header.KeyID)
	}
	if !found || !current {
		return VerifiedIdentity{}, authenticationFailure("access-assertion")
	}
	payload, err := signed.Verify(key.Key)
	if err != nil {
		return VerifiedIdentity{}, authenticationFailure("access-assertion")
	}
	var claims jwt.Claims
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Subject == "" || claims.IssuedAt == nil || claims.Expiry == nil || len(claims.Audience) == 0 {
		return VerifiedIdentity{}, authenticationFailure("access-assertion")
	}
	now := adapter.clock().UTC()
	expected := jwt.Expected{Issuer: adapter.config.Issuer, AnyAudience: jwt.Audience{adapter.config.Audience}, Time: now}
	if err := claims.ValidateWithLeeway(expected, adapter.config.ClockSkew); err != nil {
		return VerifiedIdentity{}, authenticationFailure("access-assertion")
	}
	verified := VerifiedIdentity{
		Issuer: claims.Issuer, Subject: claims.Subject, Audiences: append([]string(nil), claims.Audience...),
		IssuedAt: claims.IssuedAt.Time().UTC(), ExpiresAt: claims.Expiry.Time().UTC(), Method: CloudflareAccessMethod,
	}
	if _, err := BindingDigest(verified); err != nil {
		return VerifiedIdentity{}, authenticationFailure("access-assertion")
	}
	return verified, nil
}

func (adapter *CloudflareAccessAdapter) cachedKey(kid string) (jose.JSONWebKey, bool, bool, uint64) {
	adapter.cacheMu.RLock()
	defer adapter.cacheMu.RUnlock()
	key, found := adapter.keys[kid]
	age := adapter.clock().UTC().Sub(adapter.lastFetch)
	current := !adapter.lastFetch.IsZero() && age >= 0 && age <= adapter.config.KnownKeyOutageLimit
	return key, found, current, adapter.refreshGeneration
}

func authenticationFailure(target string) error {
	return failure.New("AUTHENTICATION_REQUIRED", target, false)
}

var _ VerifiedIdentityAdapter = (*CloudflareAccessAdapter)(nil)

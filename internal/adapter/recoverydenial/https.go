package recoverydenial

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"
)

const HTTPSImplementationDigest = "sha256:7c8db8ea2b9fb723f4bfa00b63e603c32e89df316643e6d17933c7f70f8f01af"
const httpsResponseDomain = "vegastack-labs.dev/direct-denial-response/v1\x00"

type HTTPSConfig struct {
	AdapterID         string `json:"adapterId"`
	Endpoint          string `json:"endpoint"`
	ObserverID        string `json:"observerId"`
	ObserverPublicKey []byte `json:"observerPublicKey"`
	RootCAPEM         []byte `json:"rootCaPem"`
}

type SignedResult struct {
	Result    Result `json:"result"`
	Signature []byte `json:"signature"`
}

type HTTPSAdapter struct {
	adapterID, observerID string
	endpoint              *url.URL
	publicKey             ed25519.PublicKey
	client                *http.Client
	clock                 func() time.Time
}

func NewHTTPSAdapter(config HTTPSConfig, clock func() time.Time) (*HTTPSAdapter, error) {
	endpoint, err := url.Parse(config.Endpoint)
	pool := x509.NewCertPool()
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Path == "" || !token.MatchString(config.AdapterID) || !token.MatchString(config.ObserverID) || len(config.ObserverPublicKey) != ed25519.PublicKeySize || len(config.RootCAPEM) == 0 || !pool.AppendCertsFromPEM(config.RootCAPEM) || clock == nil {
		return nil, ErrDenialUnavailable
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: endpoint.Hostname()}, DisableCompression: true, ForceAttemptHTTP2: true}
	client := &http.Client{Timeout: 15 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrDenialUnavailable }}
	return &HTTPSAdapter{adapterID: config.AdapterID, observerID: config.ObserverID, endpoint: endpoint, publicKey: append(ed25519.PublicKey(nil), config.ObserverPublicKey...), client: client, clock: clock}, nil
}

func CanonicalSignedResult(result Result) ([]byte, error) {
	raw, err := json.Marshal(result)
	if err != nil {
		return nil, ErrDenialUnavailable
	}
	return append([]byte(httpsResponseDomain), raw...), nil
}

func (adapter *HTTPSAdapter) Probe(ctx context.Context, challenge Challenge) (Result, error) {
	if adapter == nil || adapter.client == nil || adapter.endpoint == nil || ctx == nil || ctx.Err() != nil || challenge.AdapterID != adapter.adapterID {
		return Result{}, ErrDenialUnavailable
	}
	now := adapter.clock().UTC()
	if ValidateResultShapeChallenge(ctx, challenge, now) != nil {
		return Result{}, ErrDenialUnavailable
	}
	body, err := json.Marshal(challenge)
	if err != nil {
		return Result{}, ErrDenialUnavailable
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, adapter.endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return Result{}, ErrDenialUnavailable
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := adapter.client.Do(request)
	if err != nil {
		return Result{}, ErrDenialUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/json" {
		return Result{}, ErrDenialUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 32*1024+1))
	if err != nil || len(raw) == 0 || len(raw) > 32*1024 {
		return Result{}, ErrDenialUnavailable
	}
	var signed SignedResult
	if json.Unmarshal(raw, &signed) != nil || len(signed.Signature) != ed25519.SignatureSize || signed.Result.ObserverID != adapter.observerID || ValidateResult(ctx, challenge, signed.Result, adapter.clock().UTC()) != nil {
		return Result{}, ErrDenialUnavailable
	}
	canonical, err := CanonicalSignedResult(signed.Result)
	if err != nil || !ed25519.Verify(adapter.publicKey, canonical, signed.Signature) {
		return Result{}, ErrDenialUnavailable
	}
	return signed.Result, nil
}

func ValidateResultShapeChallenge(ctx context.Context, challenge Challenge, now time.Time) error {
	placeholder := Result{ChallengeID: challenge.ChallengeID, Kind: challenge.Kind, SubjectID: challenge.SubjectID, TargetID: challenge.TargetID, AdapterID: challenge.AdapterID, FormerIdentityID: challenge.FormerIdentityID, ProbeID: challenge.ProbeID, ObserverID: "observer-placeholder", ResponseClass: "direct-denial", ResponseDigest: "sha256:" + hex.EncodeToString(sha256.New().Sum(nil)), ObservedAt: now, ExpiresAt: now.Add(time.Second), SessionExpiry: now.Add(time.Second), Denied: true}
	return ValidateResult(ctx, challenge, placeholder, now)
}

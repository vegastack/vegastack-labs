package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/recovery"
)

const systemRecoveryCanaryConfigPath = "/etc/vsk-labs/recovery/canary-capabilities.json"
const recoveryCanaryResponseDomain = "vegastack-labs.dev/recovery-canary-capability-response/v1\x00"

type recoveryCanaryCapabilityConfig struct {
	Schema            string `json:"schema"`
	SchemaVersion     string `json:"schemaVersion"`
	Endpoint          string `json:"endpoint"`
	ObserverID        string `json:"observerId"`
	ObserverPublicKey []byte `json:"observerPublicKey"`
	RootCAPEM         []byte `json:"rootCaPem"`
}

type recoveryCanaryCapabilityRequest struct {
	Action    string                 `json:"action"`
	Canary    recovery.CanaryRequest `json:"canary"`
	NoopRunID string                 `json:"noopRunId,omitempty"`
}

type recoveryCanaryCapabilityResult struct {
	Action            string    `json:"action"`
	PlanID            string    `json:"planId"`
	PlanDigest        string    `json:"planDigest"`
	CanaryRunID       string    `json:"canaryRunId"`
	CanaryStepID      string    `json:"canaryStepId"`
	CanaryChallengeID string    `json:"canaryChallengeId"`
	CanaryReceiptID   string    `json:"canaryReceiptId"`
	ObserverID        string    `json:"observerId"`
	OutputID          string    `json:"outputId"`
	RepositoryClass   string    `json:"repositoryClass,omitempty"`
	ObservedAt        time.Time `json:"observedAt"`
}

type signedRecoveryCanaryCapabilityResult struct {
	Result    recoveryCanaryCapabilityResult `json:"result"`
	Signature []byte                         `json:"signature"`
}

type systemRecoveryCanaryCapabilities struct {
	load  func() (recoveryCanaryCapabilityConfig, error)
	clock func() time.Time
}

func NewSystemRecoveryCanaryCapabilities() *systemRecoveryCanaryCapabilities {
	return &systemRecoveryCanaryCapabilities{load: readSystemRecoveryCanaryCapabilityConfig, clock: time.Now}
}

func (capability *systemRecoveryCanaryCapabilities) AppendRecoveryCheckpoint(ctx context.Context, request recovery.CanaryRequest, noopRunID string) (string, error) {
	result, err := capability.invoke(ctx, recoveryCanaryCapabilityRequest{Action: "append-checkpoint", Canary: request, NoopRunID: noopRunID})
	if err != nil || result.RepositoryClass != "" || noopRunID != request.CanaryRunID {
		return "", failure.New(generated.ErrorCodePrerequisiteBlocked, "recovery-canary-audit", false)
	}
	return result.OutputID, nil
}

func (capability *systemRecoveryCanaryCapabilities) CreateRecoveryBackup(ctx context.Context, request recovery.CanaryRequest) (string, string, error) {
	result, err := capability.invoke(ctx, recoveryCanaryCapabilityRequest{Action: "create-backup", Canary: request})
	if err != nil || result.RepositoryClass != "standard" && result.RepositoryClass != "critical" {
		return "", "", failure.New(generated.ErrorCodePrerequisiteBlocked, "recovery-canary-backup", false)
	}
	return result.OutputID, result.RepositoryClass, nil
}

func (capability *systemRecoveryCanaryCapabilities) invoke(ctx context.Context, request recoveryCanaryCapabilityRequest) (recoveryCanaryCapabilityResult, error) {
	blocked := func() (recoveryCanaryCapabilityResult, error) {
		return recoveryCanaryCapabilityResult{}, failure.New(generated.ErrorCodePrerequisiteBlocked, "recovery-canary-capability", false)
	}
	if capability == nil || capability.load == nil || capability.clock == nil || ctx == nil || ctx.Err() != nil || request.Action == "" || request.Canary.StartedAt.IsZero() {
		return blocked()
	}
	config, err := capability.load()
	endpoint, parseErr := url.Parse(config.Endpoint)
	pool := x509.NewCertPool()
	if err != nil || parseErr != nil || config.Schema != "vegastack-labs.dev/recovery-canary-capabilities" || config.SchemaVersion != "1.0.0" || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Path == "" || config.ObserverID == "" || len(config.ObserverPublicKey) != ed25519.PublicKeySize || !pool.AppendCertsFromPEM(config.RootCAPEM) {
		return blocked()
	}
	body, err := json.Marshal(request)
	if err != nil {
		return blocked()
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return blocked()
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: endpoint.Hostname()}, DisableCompression: true, ForceAttemptHTTP2: true}, CheckRedirect: func(*http.Request, []*http.Request) error {
		return failure.New(generated.ErrorCodeAuthorizationDenied, "recovery-canary-capability", false)
	}}
	response, err := client.Do(httpRequest)
	if err != nil {
		return blocked()
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 32*1024+1))
	if err != nil || response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/json" || len(raw) == 0 || len(raw) > 32*1024 {
		return blocked()
	}
	var signed signedRecoveryCanaryCapabilityResult
	if json.Unmarshal(raw, &signed) != nil || len(signed.Signature) != ed25519.SignatureSize {
		return blocked()
	}
	result := signed.Result
	now := capability.clock().UTC()
	if result.Action != request.Action || result.PlanID != request.Canary.PlanID || result.PlanDigest != request.Canary.PlanDigest || result.CanaryRunID != request.Canary.CanaryRunID || result.CanaryStepID != request.Canary.CanaryStepID || result.CanaryChallengeID != request.Canary.CanaryChallengeID || result.CanaryReceiptID != request.Canary.CanaryReceiptID || result.ObserverID != config.ObserverID || result.OutputID == "" || result.ObservedAt.Before(request.Canary.StartedAt) || result.ObservedAt.After(now) || now.Sub(result.ObservedAt) > 60*time.Second {
		return blocked()
	}
	canonical, err := json.Marshal(result)
	if err != nil || !ed25519.Verify(config.ObserverPublicKey, append([]byte(recoveryCanaryResponseDomain), canonical...), signed.Signature) {
		return blocked()
	}
	return result, nil
}

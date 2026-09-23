//go:build recovery_disposable && linux

package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter/recoverydenial"
)

// This adapter is compiled only for the disposable acceptance binary. Its
// endpoint is loopback-only and accepts a synthetic old identity token.
type disposableHTTPDenialAdapter struct{ endpoint string }

func disposableWitnessAdapters() map[string]recoverydenial.Adapter {
	if os.Getenv("VSK_WITNESS_COLLECT_DISPOSABLE") != "1" || os.Geteuid() != 21001 {
		return nil
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		return nil
	}
	endpoint := os.Getenv("VSK_WITNESS_COLLECT_ENDPOINT")
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "http" || parsed.Hostname() != "127.0.0.1" || parsed.Port() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" {
		return nil
	}
	return map[string]recoverydenial.Adapter{"disposable-http-v1": disposableHTTPDenialAdapter{endpoint: endpoint}}
}

type disposableProbe struct {
	ChallengeID, TargetID, FormerIdentityID, ProbeID string
}
type disposableResponse struct{ ChallengeID, ProbeID, Class string }

func (adapter disposableHTTPDenialAdapter) Probe(ctx context.Context, challenge recoverydenial.Challenge) (recoverydenial.Result, error) {
	input, err := json.Marshal(disposableProbe{ChallengeID: challenge.ChallengeID, TargetID: challenge.TargetID, FormerIdentityID: challenge.FormerIdentityID, ProbeID: challenge.ProbeID})
	if err != nil {
		return recoverydenial.Result{}, recoverydenial.ErrDenialUnavailable
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, adapter.endpoint+"/probe", bytes.NewReader(input))
	if err != nil {
		return recoverydenial.Result{}, recoverydenial.ErrDenialUnavailable
	}
	request.Header.Set("X-Synthetic-Old-Identity", "old-token")
	client := &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return recoverydenial.Result{}, recoverydenial.ErrDenialUnavailable
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1025))
	if err != nil || len(body) > 1024 || response.StatusCode != http.StatusForbidden {
		return recoverydenial.Result{}, recoverydenial.ErrDenialUnavailable
	}
	var decoded disposableResponse
	if json.Unmarshal(body, &decoded) != nil || decoded.ChallengeID != challenge.ChallengeID || decoded.ProbeID != challenge.ProbeID || decoded.Class != "direct-denial" {
		return recoverydenial.Result{}, recoverydenial.ErrDenialUnavailable
	}
	sum := sha256.Sum256(body)
	now := time.Now().UTC()
	return recoverydenial.Result{ChallengeID: challenge.ChallengeID, Kind: challenge.Kind, SubjectID: challenge.SubjectID, TargetID: challenge.TargetID, AdapterID: challenge.AdapterID, FormerIdentityID: challenge.FormerIdentityID, ProbeID: challenge.ProbeID, ObserverID: "disposable-custodian", ResponseClass: decoded.Class, ResponseDigest: "sha256:" + hex.EncodeToString(sum[:]), ObservedAt: now, ExpiresAt: challenge.Deadline, SessionExpiry: challenge.Deadline, Denied: true}, nil
}

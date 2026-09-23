package r2

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/adapter/r2retention"
	"github.com/vegastack/vegastack-labs/internal/backup"
)

type RetentionClient struct {
	APIBase, AccountID, Bucket string
	Client                     *http.Client
	Clock                      func() time.Time
	AvailableBytes             int64
	AvailablePUTs              int64
	AvailableLISTs             int64
	RuleCount                  int
	RuleLimit                  int
	RetainedGenerations        int
}

func (client RetentionClient) ReadRulesWithBearer(ctx context.Context, bucket string, bearer []byte) (r2retention.RuleSet, error) {
	if bucket != client.Bucket {
		return r2retention.RuleSet{}, errors.New("r2 retention bucket mismatch")
	}
	payload, err := client.readRulePayload(ctx, bearer)
	if err != nil {
		return r2retention.RuleSet{}, err
	}
	rules := make([]r2retention.Rule, 0, len(payload))
	for _, rule := range payload {
		if !rule.Enabled || rule.Condition.Type != "Indefinite" || rule.ID == "" || rule.Prefix == "" {
			return r2retention.RuleSet{}, errors.New("r2 retention rule shape unsupported")
		}
		rules = append(rules, r2retention.Rule{RuleID: rule.ID, Prefix: rule.Prefix})
	}
	return r2retention.RuleSet{Rules: rules}, nil
}

func (client RetentionClient) PutRulesWithBearer(ctx context.Context, bucket string, set r2retention.RuleSet, bearer []byte) error {
	if bucket != client.Bucket || len(bearer) == 0 {
		return errors.New("r2 retention writer unavailable")
	}
	rules := make([]retentionRulePayload, len(set.Rules))
	for index, rule := range set.Rules {
		if rule.RuleID == "" || rule.Prefix == "" {
			return errors.New("r2 retention rule invalid")
		}
		rules[index] = retentionRulePayload{ID: rule.RuleID, Prefix: rule.Prefix, Enabled: true}
		rules[index].Condition.Type = "Indefinite"
	}
	body, _ := json.Marshal(struct {
		Rules []retentionRulePayload `json:"rules"`
	}{Rules: rules})
	request, err := client.ruleRequest(ctx, http.MethodPut, bytes.NewReader(body), bearer)
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	httpClient := client.Client
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	var result struct {
		Success bool `json:"success"`
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 || json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&result) != nil || !result.Success {
		return errors.New("r2 retention update failed")
	}
	return nil
}

type retentionRulePayload struct {
	ID        string `json:"id"`
	Prefix    string `json:"prefix"`
	Enabled   bool   `json:"enabled"`
	Condition struct {
		Type string `json:"type"`
	} `json:"condition"`
}

func (client RetentionClient) readRulePayload(ctx context.Context, bearer []byte) ([]retentionRulePayload, error) {
	request, err := client.ruleRequest(ctx, http.MethodGet, nil, bearer)
	if err != nil {
		return nil, err
	}
	httpClient := client.Client
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	var payload struct {
		Success bool `json:"success"`
		Result  struct {
			Rules []retentionRulePayload `json:"rules"`
		} `json:"result"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&payload) != nil || !payload.Success {
		return nil, errors.New("r2 retention observation failed")
	}
	return payload.Result.Rules, nil
}

func (client RetentionClient) ruleRequest(ctx context.Context, method string, body io.Reader, bearer []byte) (*http.Request, error) {
	base := client.APIBase
	if base == "" {
		base = "https://api.cloudflare.com/client/v4"
	}
	parsed, err := url.Parse(base)
	loopback := err == nil && parsed != nil && parsed.Scheme == "http" && client.Client != nil && net.ParseIP(parsed.Hostname()) != nil && net.ParseIP(parsed.Hostname()).IsLoopback()
	if err != nil || parsed == nil || (parsed.Scheme != "https" && !loopback) || parsed.Host == "" || client.AccountID == "" || client.Bucket == "" || len(bearer) == 0 {
		return nil, errors.New("r2 retention client unavailable")
	}
	parsed.Path += "/accounts/" + url.PathEscape(client.AccountID) + "/r2/buckets/" + url.PathEscape(client.Bucket) + "/lock"
	request, err := http.NewRequestWithContext(ctx, method, parsed.String(), body)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+string(bearer))
	return request, nil
}

func (client RetentionClient) Observe(ctx context.Context, generationID, prefix string, bearer []byte) (adapter.RetentionObservation, error) {
	base := client.APIBase
	if base == "" {
		base = "https://api.cloudflare.com/client/v4"
	}
	parsed, err := url.Parse(base)
	loopbackTest := err == nil && parsed != nil && parsed.Scheme == "http" && client.Client != nil && net.ParseIP(parsed.Hostname()) != nil && net.ParseIP(parsed.Hostname()).IsLoopback()
	if err != nil || parsed == nil || (parsed.Scheme != "https" && !loopbackTest) || parsed.Host == "" || client.AccountID == "" || client.Bucket == "" || len(bearer) == 0 {
		return adapter.RetentionObservation{}, errors.New("r2 retention observer unavailable")
	}
	parsed.Path += "/accounts/" + url.PathEscape(client.AccountID) + "/r2/buckets/" + url.PathEscape(client.Bucket) + "/lock"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return adapter.RetentionObservation{}, err
	}
	request.Header.Set("Authorization", "Bearer "+string(bearer))
	httpClient := client.Client
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return adapter.RetentionObservation{}, err
	}
	defer response.Body.Close()
	var payload struct {
		Success bool `json:"success"`
		Result  struct {
			Rules []struct {
				ID        string `json:"id"`
				Prefix    string `json:"prefix"`
				Enabled   bool   `json:"enabled"`
				Condition struct {
					Type string `json:"type"`
				} `json:"condition"`
			} `json:"rules"`
		} `json:"result"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
	if response.StatusCode != http.StatusOK || decoder.Decode(&payload) != nil || !payload.Success {
		return adapter.RetentionObservation{}, errors.New("r2 retention observation failed")
	}
	wantPrefixes := map[string]bool{}
	for _, suffix := range []string{"config", "keys/", "data/", "index/", "snapshots/"} {
		wantPrefixes[strings.TrimSuffix(prefix, "/")+"/"+suffix] = true
	}
	protected := make([]adapter.RetentionRule, 0, 5)
	for _, rule := range payload.Result.Rules {
		if wantPrefixes[rule.Prefix] && rule.Enabled && rule.Condition.Type == "Indefinite" {
			protected = append(protected, adapter.RetentionRule{RuleID: rule.ID, Prefix: rule.Prefix})
		}
	}
	if len(payload.Result.Rules) != client.RuleCount {
		return adapter.RetentionObservation{}, errors.New("r2 retention rule count mismatch")
	}
	sort.Slice(protected, func(i, j int) bool {
		if protected[i].Prefix == protected[j].Prefix {
			return protected[i].RuleID < protected[j].RuleID
		}
		return protected[i].Prefix < protected[j].Prefix
	})
	now := time.Now().UTC()
	if client.Clock != nil {
		now = client.Clock().UTC()
	}
	observation := adapter.RetentionObservation{GenerationID: generationID, ProtectedRules: protected, MutablePrefixes: []string{strings.TrimSuffix(prefix, "/") + "/locks/"}, RuleCount: len(payload.Result.Rules), RuleLimit: client.RuleLimit,
		RetainedGenerations: client.RetainedGenerations, AvailableBytes: client.AvailableBytes, AvailablePUTs: client.AvailablePUTs, AvailableLISTs: client.AvailableLISTs,
		ObservedAt: now, IndefiniteProtection: len(protected) == 5, ProofClass: "qualified-provider"}
	observation.RuleDigest = backup.DigestRetentionObservation(observation)
	return observation, nil
}

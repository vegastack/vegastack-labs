package r2

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
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
	protected := make([]adapter.RetentionRule, 0, 5)
	for _, rule := range payload.Result.Rules {
		if rule.Enabled && rule.Condition.Type == "Indefinite" {
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
	observation := adapter.RetentionObservation{GenerationID: generationID, ProtectedRules: protected, MutablePrefixes: []string{prefix + "/locks/"}, RuleCount: client.RuleCount, RuleLimit: client.RuleLimit,
		RetainedGenerations: client.RetainedGenerations, AvailableBytes: client.AvailableBytes, AvailablePUTs: client.AvailablePUTs, AvailableLISTs: client.AvailableLISTs,
		ObservedAt: now, IndefiniteProtection: len(protected) == 5, ProofClass: "qualified-provider"}
	observation.RuleDigest = backup.DigestRetentionObservation(observation)
	return observation, nil
}

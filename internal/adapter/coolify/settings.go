package coolify

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/servicecatalog"
	"net/http"
	"strconv"
)

// ImageSettings is a bounded projection of the pinned v4.3.10 application PATCH.
// It deliberately excludes commands, secrets, volumes and arbitrary Docker flags.
type ImageSettings struct {
	CPU               string `json:"limits_cpus"`
	Memory            string `json:"limits_memory"`
	MemoryReservation string `json:"limits_memory_reservation"`
	Ports             string `json:"ports_exposes"`
	HealthEnabled     bool   `json:"health_check_enabled"`
	HealthPath        string `json:"health_check_path"`
	HealthPort        string `json:"health_check_port"`
	HealthMethod      string `json:"health_check_method"`
	HealthCode        int64  `json:"health_check_return_code"`
	HealthScheme      string `json:"health_check_scheme"`
	HealthInterval    int64  `json:"health_check_interval"`
	HealthTimeout     int64  `json:"health_check_timeout"`
	HealthRetries     int64  `json:"health_check_retries"`
}

func Settings(c generated.ServiceConfiguration) (ImageSettings, error) {
	if servicecatalog.ValidateConfiguration(c) != nil {
		return ImageSettings{}, ErrInput
	}
	return ImageSettings{CPU: strconv.FormatFloat(float64(c.CPUQuotaPercent)/100, 'f', 2, 64), Memory: strconv.FormatInt(c.MemoryBytes, 10), MemoryReservation: strconv.FormatInt(c.MemoryBytes, 10), Ports: strconv.FormatInt(c.Port, 10), HealthEnabled: true, HealthPath: c.HealthPath, HealthPort: strconv.FormatInt(c.Port, 10), HealthMethod: "GET", HealthCode: c.HealthExpectedStatus, HealthScheme: "http", HealthInterval: c.HealthIntervalSeconds, HealthTimeout: c.HealthTimeoutSeconds, HealthRetries: c.HealthRetries}, nil
}
func (c *Client) VerifyImageSettings(ctx context.Context, app string, want ImageSettings, v *credentialref.Value, check func() error) error {
	// Safe projection decoder ignores all secret-bearing fields. The ordinary
	// request scanner still rejects duplicate keys and oversized responses.
	var actual ImageSettings
	if e := c.deploymentRequest(ctx, http.MethodGet, "/applications/"+app, nil, v, check, &actual); e != nil {
		return e
	}
	// Normalize equivalent decimal CPU forms; all other fields are exact.
	cpu, e := strconv.ParseFloat(actual.CPU, 64)
	expected, x := strconv.ParseFloat(want.CPU, 64)
	if e != nil || x != nil || cpu != expected {
		return ErrIdentity
	}
	actual.CPU = want.CPU
	a, _ := json.Marshal(actual)
	b, _ := json.Marshal(want)
	if string(a) != string(b) {
		return ErrIdentity
	}
	return nil
}

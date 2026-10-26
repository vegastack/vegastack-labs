package servicecatalog

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"testing"
)

func TestServiceConfigurationRejectsUnsafeRecoveryAndHealth(t *testing.T) {
	c := generated.ServiceConfiguration{Schema: "vegastack-labs.dev/service-configuration", SchemaVersion: "1.0.0", EnvironmentClass: "development", CPUQuotaPercent: 100, MemoryBytes: 268435456, Port: 8080, Exposure: "private", HealthPath: "/ready", HealthExpectedStatus: 200, HealthIntervalSeconds: 10, HealthTimeoutSeconds: 2, HealthRetries: 3, DataClass: "stateless", Migration: "none", Rollback: "previous-artifact", SecretReferenceIDs: []string{}}
	if ValidateConfiguration(c) != nil {
		t.Fatal("valid configuration rejected")
	}
	for _, mutate := range []func(*generated.ServiceConfiguration){func(c *generated.ServiceConfiguration) { c.HealthPath = "/ready;touch" }, func(c *generated.ServiceConfiguration) { c.HealthPath = "//external.example/" }, func(c *generated.ServiceConfiguration) { c.DataClass = "stateful" }, func(c *generated.ServiceConfiguration) { c.Migration = "irreversible" }, func(c *generated.ServiceConfiguration) { c.SecretReferenceIDs = []string{"plaintext value"} }} {
		bad := c
		mutate(&bad)
		if ValidateConfiguration(bad) == nil {
			t.Fatalf("unsafe configuration accepted: %+v", bad)
		}
	}
}

func TestSealedEnvironmentBindingsRejectPlaintextValueFields(t *testing.T) {
	raw := []byte(`{"schema":"vegastack-labs.dev/service-environment-secret","schemaVersion":"1.0.0","name":"APP_KEY","referenceId":"application-key","expectedFingerprint":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","value":"private-value"}`)
	if generated.ValidateContractJSON(generated.SchemaIDServiceEnvironmentSecret, raw, generated.ContractExact) == nil {
		t.Fatal("plaintext accepted in metadata-only environment contract")
	}
}

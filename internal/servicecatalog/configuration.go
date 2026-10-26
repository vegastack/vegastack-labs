package servicecatalog

import (
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/principal"
	"net/url"
	"regexp"
	"strings"
	"time"
)

func configurationFailure() error {
	return failure.New(generated.ErrorCodePrerequisiteBlocked, "service-configuration", false)
}
func ValidateConfiguration(c generated.ServiceConfiguration) error {
	raw, e := json.Marshal(c)
	if e != nil || generated.ValidateContractJSON(generated.SchemaIDServiceConfiguration, raw, generated.ContractExact) != nil {
		return configurationFailure()
	}
	u, e := url.Parse(c.HealthPath)
	if e != nil || u.IsAbs() || u.Host != "" || !strings.HasPrefix(c.HealthPath, "/") || strings.HasPrefix(c.HealthPath, "//") || !regexp.MustCompile(`^/[A-Za-z0-9/._~-]*$`).MatchString(c.HealthPath) || u.Fragment != "" || u.RawQuery != "" || strings.ContainsAny(c.HealthPath, "\r\n\\") || c.HealthTimeoutSeconds > c.HealthIntervalSeconds {
		return configurationFailure()
	}
	// Workload secret injection is outside the current typed image adapter. A
	// declared unresolved consumer must block rather than silently omit a secret.
	for _, id := range c.SecretReferenceIDs {
		if !principal.ValidID(id) {
			return configurationFailure()
		}
	}
	if (c.Exposure == "public" && (c.ExposurePolicyID == "" || c.OriginIdentityDigest == "" || c.OriginPort < 1 || !regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$`).MatchString(c.ExposureHostname))) || (c.Exposure == "private" && (c.ExposurePolicyID != "" || c.OriginIdentityDigest != "" || c.ExposureHostname != "" || c.OriginPort != 0)) {
		return configurationFailure()
	}
	if c.DataClass == "stateless" {
		if c.Migration != "none" || c.Rollback != "previous-artifact" || c.BackupPolicyID != "" || c.ConsistencyProcedureID != "" || c.RecoveryRecordID != "" || c.RecoveryObjectiveSeconds != 0 {
			return configurationFailure()
		}
	} else if c.BackupPolicyID == "" || c.ConsistencyProcedureID == "" || c.RecoveryRecordID == "" || c.RecoveryObjectiveSeconds <= 0 || c.Migration == "none" {
		return configurationFailure()
	}
	if c.Migration == "irreversible" && c.Rollback != "recovery-required" {
		return configurationFailure()
	}
	return nil
}
func ValidateCapacity(c generated.ServiceCapacity, hostID, identity, target string, epoch int64, at time.Time) error {
	raw, e := json.Marshal(c)
	observed, oe := time.Parse(time.RFC3339, c.ObservedAt)
	expires, ee := time.Parse(time.RFC3339, c.ExpiresAt)
	if e != nil || generated.ValidateContractJSON(generated.SchemaIDServiceCapacity, raw, generated.ContractExact) != nil || c.HostID != hostID || c.HostIdentityDigest != identity || c.TargetDigest != target || c.RecoveryEpoch != epoch || oe != nil || ee != nil || observed.After(at.Add(time.Second)) || !at.Before(expires) || expires.Sub(observed) > 30*time.Minute || !expires.After(observed) {
		return configurationFailure()
	}
	return nil
}

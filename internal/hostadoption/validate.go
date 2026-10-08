// Package hostadoption validates database-only registration; it never admits workloads.
package hostadoption

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"strings"
	"time"
)

func IdentityDigest(kind, value string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d:%s%d:%s", len(kind), kind, len(value), value)))
	return "sha256:" + hex.EncodeToString(sum[:])
}
func Digest(r generated.HostAdoptionRequest) string { return hostdiscovery.Digest(r) }
func Validate(r generated.HostAdoptionRequest, o generated.HostObservation, t generated.HostDiscoveryTarget, now time.Time) error {
	deny := func() error { return failure.New(generated.ErrorCodePrerequisiteBlocked, "host-adoption", false) }
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > 16384 || generated.ValidateContractJSON(generated.SchemaIDHostAdoptionRequest, raw, generated.ContractExact) != nil {
		return deny()
	}
	copy := o
	copy.ContentDigest = ""
	if o.ContentDigest != hostdiscovery.Digest(copy) || r.ObservationID != o.ObservationID || r.ObservationDigest != o.ContentDigest || o.TargetID != t.TargetID || o.TargetRevision != t.Revision || r.Confirmation.TargetRevision != t.Revision || r.Confirmation.TargetDigest != o.TargetDigest || r.RecoveryEpoch != o.RecoveryEpoch || r.RecoveryEpoch != t.RecoveryEpoch {
		return deny()
	}
	observed, e1 := time.Parse(time.RFC3339, o.ObservedAt)
	expires, e2 := time.Parse(time.RFC3339, o.ExpiresAt)
	confirmed, e3 := time.Parse(time.RFC3339, r.Confirmation.ConfirmedAt)
	if e1 != nil || e2 != nil || e3 != nil || !now.Before(expires) || observed.After(now) || !expires.After(observed) || expires.Sub(observed) > hostdiscovery.Freshness || confirmed.Before(observed) || confirmed.After(now) || !confirmed.Before(expires) {
		return deny()
	}
	if t.ExpectedOS != "debian" || t.ExpectedArchitecture != "amd64" || (t.ExpectedVersion != "13" && t.ExpectedVersion != "13.6") || t.ProfileID != "debian-13-amd64" {
		return deny()
	}
	facts := map[string]string{}
	for _, f := range o.Facts {
		if _, ok := facts[f.Name]; ok {
			return deny()
		}
		facts[f.Name] = f.Value
	}
	for _, blocker := range o.Blockers {
		if blocker == "identity-conflict" || blocker == "inventory-identity-mismatch" || blocker == "os-version-conflict" || blocker == "os-mismatch" || blocker == "os-version-mismatch" || blocker == "architecture-mismatch" || blocker == "unsupported-profile" || blocker == "stale-observation" {
			return deny()
		}
	}
	if facts["os.id"] != "debian" || facts["os.version"] != "13" || facts["architecture"] != "amd64" || (facts["os.point-version"] != "" && strings.SplitN(facts["os.point-version"], ".", 2)[0] != "13") || (t.ExpectedVersion == "13.6" && facts["os.point-version"] != "13.6") {
		return deny()
	}
	kind := "product-serial"
	if r.Confirmation.IdentityClass == "qualified-virtual" {
		kind = "product-uuid"
	}
	value := facts[kind]
	if r.Confirmation.IdentityKind != kind || strings.TrimSpace(value) == "" || r.Confirmation.IdentityDigest != IdentityDigest(kind, value) {
		return deny()
	}
	return nil
}

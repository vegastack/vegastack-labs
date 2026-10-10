// Package qualification drives the finite disposable native fixture. Public
// reports are diagnostics; only the existing internally collected gate path
// can confer qualification.
package qualification

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/debianaccess"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/strictjson"
)

var ErrUnavailable = errors.New("native qualification prerequisite unavailable")
var ownedPath = regexp.MustCompile(`^/[A-Za-z0-9_./-]+$`)
var identifier = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)

const GiB int64 = 1024 * 1024 * 1024

// validatedNativeScope can only be constructed by exact structural validation;
// native ownership and suitability are separately required before connection.
type validatedNativeScope struct {
	value  generated.QualificationScope
	digest string
	guests map[string]generated.QualificationGuest
}

func DecodeScope(raw []byte) (generated.QualificationScope, error) {
	var scope generated.QualificationScope
	if len(raw) == 0 || len(raw) > 65536 || strictjson.Scan(context.Background(), raw, strictjson.Limits{MaxDepth: 12}) != nil || generated.ValidateContractJSON(generated.SchemaIDQualificationScope, raw, generated.ContractExact) != nil || json.Unmarshal(raw, &scope) != nil {
		return scope, ErrUnavailable
	}
	_, err := validateScope(scope)
	return scope, err
}
func ValidateScope(scope generated.QualificationScope) error {
	_, err := validateScope(scope)
	return err
}
func validateScope(scope generated.QualificationScope) (validatedNativeScope, error) {
	var out validatedNativeScope
	raw, err := json.Marshal(scope)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDQualificationScope, raw, generated.ContractExact) != nil || !identifier.MatchString(scope.RunID) || debianaccess.ProtectedName(scope.PhysicalHostID) || !identifier.MatchString(scope.PhysicalHostID) || scope.MaximumDurationSeconds > 14400 || !filepath.IsAbs(scope.OutputRoot) || filepath.Clean(scope.OutputRoot) != scope.OutputRoot || scope.OutputRoot == "/" || !ownedPath.MatchString(scope.OutputRoot) || strings.ContainsAny(scope.OutputRoot, "\x00\n\r") {
		return out, ErrUnavailable
	}
	issued, e := time.Parse(time.RFC3339, scope.IssuedAt)
	expires, f := time.Parse(time.RFC3339, scope.ExpiresAt)
	if e != nil || f != nil || !expires.After(issued) || expires.Sub(issued) > time.Duration(scope.MaximumDurationSeconds)*time.Second || expires.Sub(issued) > 4*time.Hour {
		return out, ErrUnavailable
	}
	r := scope.Resources
	if r.CPUs > 6 || r.MemoryBytes > 8*GiB || r.StorageBytes > 80*GiB || len(scope.Guests) < 2 || len(scope.Guests) > 4 {
		return out, ErrUnavailable
	}
	guests := map[string]generated.QualificationGuest{}
	roles := map[string]bool{}
	instances := map[string]bool{}
	keys := map[string]bool{}
	hosts := map[string]bool{}
	identities := map[string]bool{}
	var cpu, memory, disk int64
	for _, g := range scope.Guests {
		if !identifier.MatchString(g.GuestID) || !identifier.MatchString(g.InstanceID) || !identifier.MatchString(g.HostID) || debianaccess.ProtectedName(g.HostID) || hosts[g.HostID] || identities[g.HostIdentityDigest] || debianaccess.ProtectedName(g.GuestID) || roles[g.Role] || instances[g.InstanceID] || keys[g.SSHHostKeyDigest] || g.CPUs > 6 || g.MemoryBytes > 7*GiB || g.MemoryBytes%(1024*1024) != 0 || g.DiskBytes > 36*GiB {
			return out, ErrUnavailable
		}
		if _, exists := guests[g.GuestID]; exists {
			return out, ErrUnavailable
		}
		guests[g.GuestID] = g
		roles[g.Role] = true
		instances[g.InstanceID] = true
		keys[g.SSHHostKeyDigest] = true
		hosts[g.HostID] = true
		identities[g.HostIdentityDigest] = true
		cpu += g.CPUs
		memory += g.MemoryBytes
		disk += g.DiskBytes
	}
	if !roles["controller"] || !roles["subject"] || cpu > r.CPUs || memory+GiB > r.MemoryBytes || disk+8*GiB > r.StorageBytes {
		return out, ErrUnavailable
	}
	return validatedNativeScope{scope, hostaction.Digest(scope), guests}, nil
}

func scopeCurrent(s validatedNativeScope, now time.Time) bool {
	issued, _ := time.Parse(time.RFC3339, s.value.IssuedAt)
	expires, _ := time.Parse(time.RFC3339, s.value.ExpiresAt)
	return !now.Before(issued) && now.Before(expires)
}

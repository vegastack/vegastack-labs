package server

import (
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"strings"
	"testing"
	"time"
)

func TestLocalSetupRejectsAuthorityInjection(t *testing.T) {
	raw := []byte(`{"schema":"vegastack-labs.dev/local-setup-request","schemaVersion":"1.0.0","approved":true}`)
	if generated.ValidateContractJSON(generated.SchemaIDLocalSetupRequest, raw, generated.ContractExact) == nil {
		t.Fatal("caller approval accepted")
	}
}

func validLocalSetupRequest(now time.Time) generated.LocalSetupRequest {
	return generated.LocalSetupRequest{Schema: generated.SchemaIDLocalSetupRequest, SchemaVersion: "1.0.0", SetupID: "setup-a", HostIdentityDigest: "sha256:" + strings.Repeat("a", 64), InitialHumanID: "human-a", ServiceUID: 1000, InitialAdministratorUID: 1000, ProfileSHA256: "sha256:" + strings.Repeat("b", 64), DatabasePath: "/protected/control.db", ReleaseManifestPath: "/protected/manifest.json", ReleaseManifestDigest: "sha256:" + strings.Repeat("c", 64), ReleasePolicyPath: "/protected/policy.json", ReleasePolicyDigest: "sha256:" + strings.Repeat("d", 64), ExecutableAssetID: "linux-amd64", ReleaseBuildID: "build-123", ExpiresAt: now.Add(time.Hour).UTC().Format(time.RFC3339), RequestNonce: strings.Repeat("n", 32), InitialReadGrants: []generated.LocalSetupReadGrant{{Schema: generated.SchemaIDLocalSetupReadGrant, SchemaVersion: "1.0.0", Capability: "database.status.read", ResourceKind: "database", ResourceID: "database"}}, InitialEffectiveGrants: []generated.LocalSetupEffectiveGrant{{Schema: generated.SchemaIDLocalSetupEffectiveGrant, SchemaVersion: "1.0.0", GrantID: "grant-a", RoleID: "infrastructure-admin", Action: "author", Capability: "gate.profile.author", ResourceKind: "profile", ResourceID: "profile-drafts", Branch: "none"}}}
}
func TestLocalSetupFiniteAuthority(t *testing.T) {
	now := time.Now()
	for name, change := range map[string]func(*generated.LocalSetupRequest){
		"root":          func(r *generated.LocalSetupRequest) { r.ServiceUID = 0; r.InitialAdministratorUID = 0 },
		"different-uid": func(r *generated.LocalSetupRequest) { r.InitialAdministratorUID++ },
		"expired":       func(r *generated.LocalSetupRequest) { r.ExpiresAt = now.UTC().Format(time.RFC3339) },
		"wildcard":      func(r *generated.LocalSetupRequest) { r.InitialReadGrants[0].ResourceID = "*" },
		"duplicate": func(r *generated.LocalSetupRequest) {
			r.InitialReadGrants = append(r.InitialReadGrants, r.InitialReadGrants[0])
		},
		"preauthorized": func(r *generated.LocalSetupRequest) { r.InitialEffectiveGrants[0].Branch = "preauthorized" },
		"wrong-branch":  func(r *generated.LocalSetupRequest) { r.InitialEffectiveGrants[0].Branch = "human" },
		"relative-path": func(r *generated.LocalSetupRequest) { r.DatabasePath = "control.db" },
		"short-nonce":   func(r *generated.LocalSetupRequest) { r.RequestNonce = "short" },
	} {
		t.Run(name, func(t *testing.T) {
			r := validLocalSetupRequest(now)
			change(&r)
			if validateLocalSetupRequest(r, now) == nil {
				t.Fatal("invalid authority accepted")
			}
		})
	}
	raw, _ := json.Marshal(validLocalSetupRequest(now))
	if err := generated.ValidateContractJSON(generated.SchemaIDLocalSetupRequest, raw, generated.ContractExact); err != nil {
		t.Fatal(err)
	}
	if err := validateLocalSetupRequest(validLocalSetupRequest(now), now); err != nil {
		t.Fatal(err)
	}
}
func TestLocalSetupStrictJSON(t *testing.T) {
	r := validLocalSetupRequest(time.Now())
	raw, _ := json.Marshal(r)
	for _, extra := range []string{`,"setupId":"changed"`, `,"privateKey":"canary"`, `,"approved":true`} {
		malformed := append(append([]byte{}, raw[:len(raw)-1]...), []byte(extra+"}")...)
		if generated.ValidateContractJSON(generated.SchemaIDLocalSetupRequest, malformed, generated.ContractExact) == nil {
			t.Fatal("hostile record accepted")
		}
	}
}

package store

import (
	"bytes"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"testing"
	"time"
)

func TestLocalSetupCannotAttachToExistingOpen(t *testing.T) {
	if _, err := normalizeConfig(Config{Mode: OpenExisting, ToolVersion: "test", BuildVersion: "test", InitialSetup: &InitialSetup{}}); err == nil {
		t.Fatal("existing-open accepted initial authority")
	}
}

func setupFixture(t *testing.T, database string, uid uint32, now time.Time) InitialSetup {
	t.Helper()
	digest := initialSetupDigest([]byte("synthetic"))
	r := generated.LocalSetupReviewRequest{Schema: "vegastack-labs.dev/local-setup-review-request", SchemaVersion: "1.0.0", SetupID: "setup-one", HostIdentityDigest: digest, InitialHumanID: "operator-one", ServiceUID: int64(uid), InitialAdministratorUID: int64(uid), ProfileSHA256: digest, DatabasePath: database, ReleaseManifestPath: "/synthetic/manifest.json", ReleaseManifestDigest: digest, ReleasePolicyPath: "/synthetic/policy.json", ReleasePolicyDigest: digest, ExecutableAssetID: "linux-arm64", ReleaseBuildID: "test", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano), RequestNonceDigest: digest,
		InitialReadGrants:      []generated.LocalSetupReadGrant{{Schema: "vegastack-labs.dev/local-setup-read-grant", SchemaVersion: "1.0.0", Capability: "control.health.read", ResourceKind: "control", ResourceID: "control"}},
		InitialEffectiveGrants: []generated.LocalSetupEffectiveGrant{{Schema: "vegastack-labs.dev/local-setup-effective-grant", SchemaVersion: "1.0.0", GrantID: "author-one", RoleID: "control-plane-admin", Action: "author", Capability: "gate.profile.author", ResourceKind: "profile", ResourceID: "profile-drafts", Branch: "none"}}}
	review := InitialSetupReview{Request: r, RequestDigest: digest, SlackProfileDigest: digest, SlackWorkspaceID: "T123", SlackUserID: "U123", SlackHumanID: r.InitialHumanID, SlackAuthorityID: "slack-one", SlackChannelID: "C123"}
	check, _ := json.Marshal(r)
	if err := generated.ValidateContractJSON(generated.SchemaIDLocalSetupReviewRequest, check, generated.ContractExact); err != nil {
		t.Fatalf("fixture contract: %v", err)
	}
	raw, err := json.Marshal(review)
	if err != nil {
		t.Fatal(err)
	}
	setup := InitialSetup{SetupID: r.SetupID, HumanID: r.InitialHumanID, RequestDigest: digest, ReviewJSON: raw, ReviewDigest: initialSetupDigest(raw), ExpiresAt: now.Add(time.Hour), ReadGrants: []InitialReadGrant{{"control.health.read", "control", "control"}}, EffectiveGrants: []InitialEffectiveGrant{{"author-one", "control-plane-admin", "author", "gate.profile.author", "profile", "profile-drafts", ""}}}
	setup.Approval = InitialSetupApproval{HumanID: setup.HumanID, AuthorityID: review.SlackAuthorityID, ReviewDigest: setup.ReviewDigest, RequestDigest: digest, DecidedAt: now.Add(-time.Minute)}
	return setup
}

func TestLocalSetupReviewBindings(t *testing.T) {
	now := time.Date(2026, 10, 8, 1, 0, 0, 0, time.UTC)
	good := setupFixture(t, "/tmp/control.db", 501, now)
	if err := validateInitialSetup(good, now); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*InitialSetup){
		"zero approval":     func(s *InitialSetup) { s.Approval = InitialSetupApproval{} },
		"wrong human":       func(s *InitialSetup) { s.HumanID = "other" },
		"wrong authority":   func(s *InitialSetup) { s.Approval.AuthorityID = "other" },
		"wrong request":     func(s *InitialSetup) { s.RequestDigest = initialSetupDigest([]byte("other")) },
		"wrong review":      func(s *InitialSetup) { s.ReviewDigest = initialSetupDigest([]byte("other")) },
		"expired":           func(s *InitialSetup) { s.ExpiresAt = now },
		"future approval":   func(s *InitialSetup) { s.Approval.DecidedAt = now.Add(time.Second) },
		"missing read":      func(s *InitialSetup) { s.ReadGrants = nil },
		"widened read":      func(s *InitialSetup) { s.ReadGrants[0].ResourceID = "other" },
		"widened effective": func(s *InitialSetup) { s.EffectiveGrants[0].ResourceID = "other" },
		"policy branch":     func(s *InitialSetup) { s.EffectiveGrants[0].Branch = "preauthorized" },
		"unknown json": func(s *InitialSetup) {
			s.ReviewJSON = append([]byte(`{"approved":true,`), s.ReviewJSON[1:]...)
			s.ReviewDigest = initialSetupDigest(s.ReviewJSON)
			s.Approval.ReviewDigest = s.ReviewDigest
		},
		"duplicate json": func(s *InitialSetup) {
			s.ReviewJSON = append([]byte(`{"requestDigest":"`+s.RequestDigest+`",`), s.ReviewJSON[1:]...)
			s.ReviewDigest = initialSetupDigest(s.ReviewJSON)
			s.Approval.ReviewDigest = s.ReviewDigest
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := setupFixture(t, "/tmp/control.db", 501, now)
			mutate(&s)
			if validateInitialSetup(s, now) == nil {
				t.Fatal("invalid setup accepted")
			}
		})
	}
	if validateInitialSetup(good, good.ExpiresAt) == nil {
		t.Fatal("transaction expiry accepted")
	}
}

func TestLocalSetupRejectsSelfConsistentUnsafeGrants(t *testing.T) {
	now := time.Date(2026, 10, 8, 1, 0, 0, 0, time.UTC)
	for _, kind := range []string{"wildcard-read", "wildcard-effective", "author-human-branch", "preauthorized-role", "duplicate-read", "duplicate-grant", "root-uid", "different-admin-uid", "unknown-grant-field", "raw-nonce"} {
		t.Run(kind, func(t *testing.T) {
			s := setupFixture(t, "/tmp/control.db", 501, now)
			var r InitialSetupReview
			if err := json.Unmarshal(s.ReviewJSON, &r); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "wildcard-read":
				r.Request.InitialReadGrants[0].ResourceID = "*"
				s.ReadGrants[0].ResourceID = "*"
			case "wildcard-effective":
				r.Request.InitialEffectiveGrants[0].ResourceID = "*"
				s.EffectiveGrants[0].ResourceID = "*"
			case "author-human-branch":
				r.Request.InitialEffectiveGrants[0].Branch = "human"
				s.EffectiveGrants[0].Branch = "human"
			case "preauthorized-role":
				r.Request.InitialEffectiveGrants[0].RoleID = "preauthorized-executor"
				s.EffectiveGrants[0].RoleID = "preauthorized-executor"
			case "duplicate-read":
				r.Request.InitialReadGrants = append(r.Request.InitialReadGrants, r.Request.InitialReadGrants[0])
				s.ReadGrants = append(s.ReadGrants, s.ReadGrants[0])
			case "duplicate-grant":
				r.Request.InitialEffectiveGrants = append(r.Request.InitialEffectiveGrants, r.Request.InitialEffectiveGrants[0])
				s.EffectiveGrants = append(s.EffectiveGrants, s.EffectiveGrants[0])
			case "root-uid":
				r.Request.ServiceUID = 0
				r.Request.InitialAdministratorUID = 0
			case "different-admin-uid":
				r.Request.InitialAdministratorUID++
			}
			s.ReviewJSON, _ = json.Marshal(r)
			if kind == "unknown-grant-field" {
				s.ReviewJSON = bytes.Replace(s.ReviewJSON, []byte(`"grantId":`), []byte(`"approved":true,"grantId":`), 1)
			}
			if kind == "raw-nonce" {
				s.ReviewJSON = bytes.Replace(s.ReviewJSON, []byte(`"requestNonceDigest":`), []byte(`"requestNonce":"synthetic","requestNonceDigest":`), 1)
			}
			s.ReviewDigest = initialSetupDigest(s.ReviewJSON)
			s.Approval.ReviewDigest = s.ReviewDigest
			if validateInitialSetup(s, now) == nil {
				t.Fatal("unsafe self-consistent setup accepted")
			}
		})
	}
}

package store

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"strings"
	"testing"
)

func TestAuthorizationGrantBatchRejectsWidening(t *testing.T) {
	request := generated.AuthorizationGrantBatchRequest{Schema: "vegastack-labs.dev/authorization-grant-batch-request", SchemaVersion: "1.0.0", PrincipalID: "operator", ExpectedGrantRevision: 1, ExpectedStateRevision: 1, IdempotencyKey: "batch", ReasonDigest: "sha256:" + strings.Repeat("a", 64), Changes: []generated.AuthorizationGrantChange{{Schema: "vegastack-labs.dev/authorization-grant-change", SchemaVersion: "1.0.0", GrantID: "host-read", Change: "add", RoleID: "reader", Action: "read", Capability: "host.read", ResourceKind: "host", ResourceID: "subject", Branch: ""}}}
	if err := ValidateAuthorizationGrantBatch(request); err != nil {
		t.Fatal(err)
	}
	for _, variant := range []string{"too-many", "duplicate", "wildcard", "branch", "admin-delegation", "seed-revoke"} {
		t.Run(variant, func(t *testing.T) {
			r := request
			r.Changes = append([]generated.AuthorizationGrantChange(nil), request.Changes...)
			switch variant {
			case "too-many":
				r.Changes = make([]generated.AuthorizationGrantChange, 33)
			case "duplicate":
				r.Changes = append(r.Changes, r.Changes[0])
			case "wildcard":
				r.Changes[0].ResourceID = "*"
			case "branch":
				r.Changes[0].Branch = "human"
			case "admin-delegation":
				r.Changes[0].Action = "author"
				r.Changes[0].Capability = "authorization.policy.write"
				r.Changes[0].ResourceKind = "authorization-policy"
			case "seed-revoke":
				r.Changes[0].Change = "revoke"
				r.Changes[0].Action = "acknowledge"
				r.Changes[0].Branch = "human"
				r.Changes[0].Capability = "plan.acknowledge"
				r.Changes[0].ResourceKind = "plan-target"
				r.Changes[0].ResourceID = r.PrincipalID
			}
			if ValidateAuthorizationGrantBatch(r) == nil {
				t.Fatal("authority widening accepted")
			}
		})
	}
}

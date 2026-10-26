package networkmesh

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"strings"
	"testing"
)

func TestClosedScope(t *testing.T) {
	c := generated.MeshChange{ProfileID: "pilot", AccountID: strings.Repeat("a", 32), Action: "profile-routing-update", ResourceKind: "profile-include", ResourceID: "default"}
	if Validate(c) == nil {
		t.Fatal("default policy accepted")
	}
}
func TestRejectNoncanonicalAndBroadRoutes(t *testing.T) {
	for _, s := range []string{"0.0.0.0/0", "vsk-node-04", "https://example.com", "100.96.1.2/12"} {
		if ValidRoute(s) {
			t.Fatalf("accepted %s", s)
		}
	}
}

func TestFoundationModeCannotReuseQualifiedProtectedScope(t *testing.T) {
	c := generated.MeshChange{AccountID: strings.Repeat("a", 32), ResourceID: "11111111-1111-4111-8111-111111111111", ResourceKind: "registration", Mode: "foundation", AffectedIdentityDigests: []string{Digest("synthetic")}}
	before := ScopeDigest(c)
	c.Mode = "qualified"
	if before == ScopeDigest(c) {
		t.Fatal("mode change retained protected target scope")
	}
}

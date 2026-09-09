package audit

import (
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/identity"
)

func TestNewAttributionRejectsUnverifiedShapesAndMarksAgentSelfReported(t *testing.T) {
	canary := "github_pat_public-test-canary"
	_, err := NewAttribution(identity.Principal{ID: canary, Method: "local-os-peer"}, nil, nil)
	if err == nil || strings.Contains(err.Error(), canary) {
		t.Fatalf("unsafe principal result = %v", err)
	}
	got, err := NewAttribution(identity.Principal{ID: "principal-test-1", Method: "local-os-peer"}, nil, &AgentMetadata{Name: "codex", SessionID: "session-test-1"})
	if err != nil || got.Agent == nil {
		t.Fatalf("attribution = %#v, %v", got, err)
	}
	event, err := EventFromDraft(EventDraft{Type: "inventory.draft.persisted", CorrelationID: "request-test-1", Attribution: got, Target: Target{Kind: "inventory-draft", ID: "draft-test-1"}}, 1, time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC), 0, 1)
	if err != nil || event.AgentSource == nil || *event.AgentSource != "self-reported" {
		t.Fatalf("agent source = %v, %v", event.AgentSource, err)
	}
}

func TestBoundedValuesRejectUnsafeTokensAndDestinations(t *testing.T) {
	digest := Fingerprint("sha256:" + strings.Repeat("a", 64))
	if err := ValidateIntentKey(IntentKey{Scope: "inventory-draft", KeyDigest: digest, RequestDigest: digest}); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"", "with space", "/private/path", `C:\\private`, "sk-public-canary"} {
		if validToken(value, 128) {
			t.Fatalf("unsafe token accepted: %q", value)
		}
	}
	if err := ValidateOutboxRequirements([]OutboxRequirement{{Destination: "primary", Enabled: true}, {Destination: "primary", Enabled: false}}); err == nil {
		t.Fatal("duplicate destination accepted")
	}
	if RetryDelay(1) != 30*time.Second || RetryDelay(8) != time.Hour {
		t.Fatalf("retry delays = %v, %v", RetryDelay(1), RetryDelay(8))
	}
}

package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/identity"
)

func publicFixtureEvent(t *testing.T) Event {
	t.Helper()
	attribution, err := NewAttribution(identity.Principal{ID: "principal-test-1", Method: "local-os-peer"}, nil, &AgentMetadata{Name: "codex", SessionID: "session-test-1"})
	if err != nil {
		t.Fatal(err)
	}
	after := Fingerprint("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	event, err := EventFromDraft(EventDraft{Type: "inventory.draft.persisted", CorrelationID: "request-test-1", Attribution: attribution, Target: Target{Kind: "inventory-draft", ID: "draft-test-1"}, After: &after}, 1, time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC), 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	return event
}

func TestCanonicalEventMatchesGoldenAndHasNoOpenPayload(t *testing.T) {
	event := publicFixtureEvent(t)
	got, digest, err := CanonicalEvent(event)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/event-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, bytes.TrimSuffix(want, []byte("\n"))) {
		t.Fatalf("canonical bytes differ:\n%s", got)
	}
	sum := sha256.Sum256(got)
	if digest != Fingerprint("sha256:"+hex.EncodeToString(sum[:])) {
		t.Fatalf("digest = %q", digest)
	}
	forbidden := regexp.MustCompile(`(?i)(payload|metadata|raw|path|prompt|secret|providerResponse)`)
	if forbidden.Match(got) {
		t.Fatalf("open or unsafe field in event: %s", got)
	}
}

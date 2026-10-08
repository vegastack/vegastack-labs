package slack

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestProviderInteractiveMetadataAndFullReview(t *testing.T) {
	raw := realisticInteractive(t)
	candidate, err := decodeCandidate(context.Background(), testConfig(), raw, time.Date(2026, 9, 13, 1, 5, 0, 0, time.UTC))
	if err != nil || candidate.Action != acknowledgement.ActionApprove || candidate.Human.ID != "person-operator" {
		t.Fatalf("normal provider metadata rejected: %v", err)
	}
	if rejectionSourcePrincipal(context.Background(), raw).ID == acknowledgement.UnknownSourcePrincipalID {
		t.Fatal("known provider actor lost")
	}
}
func TestProviderInteractiveStillRejectsInvalidAuthority(t *testing.T) {
	raw := string(realisticInteractive(t))
	for name, value := range map[string]string{
		"wrong-human":     strings.Replace(raw, `"id":"user-approved"`, `"id":"user-wrong"`, 1),
		"wrong-team":      strings.Replace(raw, `"id":"workspace-approved"`, `"id":"workspace-wrong"`, 1),
		"wrong-action":    strings.Replace(raw, `"action_id":"action-approve"`, `"action_id":"action-wrong"`, 1),
		"duplicate-human": strings.Replace(raw, `"id":"user-approved"`, `"id":"user-approved","id":"user-approved"`, 1),
		"wrong-type":      strings.Replace(raw, `"id":"user-approved"`, `"id":123`, 1),
		"trailing":        raw + `{}`,
		"oversize":        strings.Repeat(" ", MaxEnvelopeBytes) + raw,
		"depth":           strings.Replace(raw, `"accepts_response_payload":true`, `"extra":`+strings.Repeat("[", MaxJSONDepth+1)+`0`+strings.Repeat("]", MaxJSONDepth+1), 1),
		"unknown-binding": strings.Replace(raw, `\"planId\":`, `\"unexpected\":true,\"planId\":`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeCandidate(context.Background(), testConfig(), []byte(value), time.Date(2026, 9, 13, 1, 5, 0, 0, time.UTC)); err == nil {
				t.Fatal("invalid authority/envelope accepted")
			}
		})
	}
}
func realisticInteractive(t *testing.T) []byte {
	t.Helper()
	var envelope map[string]any
	if err := json.Unmarshal([]byte(fixtureInteractive("env-realistic", "workspace-approved", "user-approved", "action-approve")), &envelope); err != nil {
		t.Fatal(err)
	}
	envelope["accepts_response_payload"] = true
	payload := envelope["payload"].(map[string]any)
	payload["api_app_id"] = "app-fixture"
	payload["container"] = map[string]any{"type": "message", "message_ts": "123.456", "channel_id": "channel-approval", "is_ephemeral": false}
	payload["team"].(map[string]any)["domain"] = "example"
	payload["user"].(map[string]any)["username"] = "example"
	payload["actions"].([]any)[0].(map[string]any)["action_ts"] = "123.789"
	payload["actions"].([]any)[0].(map[string]any)["type"] = "button"
	payload["message"] = map[string]any{"text": strings.Repeat("<", 32<<10), "ts": "123.456"}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestProviderPublishRejectsMalformedResponses(t *testing.T) {
	for name, body := range map[string]string{
		"duplicate":        `{"ok":true,"ok":true}`,
		"type":             `{"ok":"true"}`,
		"trailing":         `{"ok":true}{}`,
		"oversize":         `{"ok":true,"metadata":"` + strings.Repeat("x", MaxEnvelopeBytes) + `"}`,
		"depth":            `{"ok":true,"metadata":` + strings.Repeat("[", MaxJSONDepth+1) + `0` + strings.Repeat("]", MaxJSONDepth+1) + `}`,
		"provider-failure": `{"ok":false,"error":"not_allowed"}`,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
			defer server.Close()
			client := server.Client()
			client.Timeout = time.Second
			client.Transport = &slackFixtureRoundTripper{base: client.Transport, origin: server.URL}
			transport, err := NewHTTPTransport(client)
			if err != nil {
				t.Fatal(err)
			}
			if err = transport.Publish(context.Background(), []byte(fixtureSlackCredential), "channel-approval", "action-approve", "action-reject", reviewTextCard("scope")); err == nil {
				t.Fatal("invalid provider response accepted")
			}
		})
	}
}

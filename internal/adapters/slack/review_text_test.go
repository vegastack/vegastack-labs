package slack

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestHTTPPublishCompleteReviewText(t *testing.T) {
	for _, test := range []struct {
		name, review string
		blocks       int
	}{
		{"ordinary", "", 0},
		{"scope", "Administrator: person-example\nDatabase: /example/control.db\nGrant: declaration.author / declaration / initial\nLiteral: <@everyone> *scope*", 1},
		{"boundary", strings.Repeat("a", 3000), 1},
		{"boundary-plus-one", strings.Repeat("a", 3001), 2},
		{"unicode-boundary", strings.Repeat("界", 2999) + "🙂é", 2},
		{"maximum", strings.Repeat("a", 32<<10), 11},
		{"maximum-escaped", strings.Repeat("<", 32<<10), 11},
	} {
		t.Run(test.name, func(t *testing.T) {
			transport, payload, calls := reviewTextTransport(t)
			card := reviewTextCard(test.review)
			if err := transport.Publish(context.Background(), []byte(fixtureSlackCredential), "channel-approval", "action-approve", "action-reject", card); err != nil {
				t.Fatal(err)
			}
			if *calls != 1 {
				t.Fatalf("HTTP calls = %d", *calls)
			}
			var got struct {
				Channel string            `json:"channel"`
				Text    string            `json:"text"`
				Blocks  []json.RawMessage `json:"blocks"`
			}
			if err := json.Unmarshal(*payload, &got); err != nil {
				t.Fatal(err)
			}
			if got.Channel != "channel-approval" || got.Text != "VegaStack plan acknowledgement required" || len(got.Blocks) != test.blocks+1 {
				t.Fatalf("unexpected publish envelope: %s", *payload)
			}
			var complete strings.Builder
			for _, raw := range got.Blocks[:test.blocks] {
				var block struct {
					Type string `json:"type"`
					Text struct {
						Type  string `json:"type"`
						Text  string `json:"text"`
						Emoji *bool  `json:"emoji"`
					} `json:"text"`
				}
				if err := json.Unmarshal(raw, &block); err != nil {
					t.Fatal(err)
				}
				if block.Type != "section" || block.Text.Type != "plain_text" || block.Text.Emoji == nil || *block.Text.Emoji || !utf8.ValidString(block.Text.Text) || utf8.RuneCountInString(block.Text.Text) > 3000 || block.Text.Text == "" {
					t.Fatalf("invalid review block: %s", raw)
				}
				complete.WriteString(block.Text.Text)
			}
			if complete.String() != test.review {
				t.Fatal("review truncated or altered")
			}
			binding, _ := json.Marshal(actionBinding{PlanID: card.Request.PlanID, PlanDigest: card.Request.PlanDigest, TargetDigest: card.Request.TargetDigest, ReasonDigest: card.Request.ReasonDigest, Nonce: card.Nonce, StateRevision: card.Request.StateRevision, RecoveryEpoch: card.Request.RecoveryEpoch, ExpiresAt: card.Request.ExpiresAt})
			actions := map[string]any{"type": "actions", "elements": []any{
				map[string]any{"type": "button", "text": map[string]string{"type": "plain_text", "text": "Approve"}, "style": "primary", "action_id": "action-approve", "value": string(binding)},
				map[string]any{"type": "button", "text": map[string]string{"type": "plain_text", "text": "Reject"}, "style": "danger", "action_id": "action-reject", "value": string(binding)},
			}}
			expectedActions, _ := json.Marshal(actions)
			if string(got.Blocks[test.blocks]) != string(expectedActions) {
				t.Fatal("action binding or buttons changed")
			}
			if test.review == "" {
				expected, _ := json.Marshal(map[string]any{"channel": "channel-approval", "text": "VegaStack plan acknowledgement required", "blocks": []any{actions}})
				if string(*payload) != string(expected) {
					t.Fatal("ordinary payload changed")
				}
			}
		})
	}
}

func TestHTTPPublishInvalidReviewMakesNoRequest(t *testing.T) {
	for _, review := range []string{strings.Repeat("a", (32<<10)+1), strings.Repeat("界", 11000), "bad\xfftext"} {
		transport, _, calls := reviewTextTransport(t)
		if err := transport.Publish(context.Background(), []byte(fixtureSlackCredential), "channel-approval", "action-approve", "action-reject", reviewTextCard(review)); err == nil {
			t.Fatal("invalid review accepted")
		}
		if *calls != 0 {
			t.Fatal("invalid review sent HTTP request")
		}
	}
}

func reviewTextCard(review string) acknowledgement.RequestCard {
	return acknowledgement.RequestCard{ReviewText: review, Nonce: "nonce-one-time", Request: generated.AcknowledgementRequest{PlanID: "plan-test", PlanDigest: slackTestDigest, TargetDigest: slackTestDigest, ReasonDigest: slackTestDigest, StateRevision: 41, RecoveryEpoch: 3, ExpiresAt: "2026-09-13T01:30:00Z"}}
}

func reviewTextTransport(t *testing.T) (*HTTPTransport, *[]byte, *int) {
	t.Helper()
	var payload []byte
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/chat" || r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer "+fixtureSlackCredential {
			t.Error("unexpected HTTP request")
		}
		var err error
		payload, err = io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		response, _ := json.Marshal(map[string]any{"ok": true, "channel": "channel-approval", "ts": "123.456", "message": json.RawMessage(payload)})
		_, _ = w.Write(response)
	}))
	t.Cleanup(server.Close)
	client := server.Client()
	client.Timeout = time.Second
	client.Transport = &slackFixtureRoundTripper{base: client.Transport, origin: server.URL}
	transport, err := NewHTTPTransport(client)
	if err != nil {
		t.Fatal(err)
	}
	return transport, &payload, &calls
}

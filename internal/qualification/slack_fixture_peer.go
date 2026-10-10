package qualification

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/strictjson"
)

// slackFixturePeer implements only Slack wire shapes consumed by the existing
// production adapter. It has no authority/store/sink, and cannot approve a card
// absent its exact protected allowlist entry. Its output is fixture provenance.
type slackFixturePeer struct {
	scope              generated.NativeSlackFixtureScope
	setup              generated.LocalSetupRequest
	appToken, botToken []byte
	approvals          func() (generated.NativeSlackFixtureApprovalList, error)
	clock              func() time.Time
	ctx                context.Context
	mu                 sync.Mutex
	tickets            map[string]time.Time
	used               map[string]bool
	queue              chan []byte
}
type fixtureActionBinding struct {
	PlanID        string `json:"planId"`
	PlanDigest    string `json:"planDigest"`
	TargetDigest  string `json:"targetDigest"`
	ReasonDigest  string `json:"reasonDigest"`
	Nonce         string `json:"nonce"`
	StateRevision int64  `json:"stateRevision"`
	RecoveryEpoch int64  `json:"recoveryEpoch"`
	ExpiresAt     string `json:"expiresAt"`
}

func fixtureDecode(ctx context.Context, raw []byte, out any, limit int) error {
	if len(raw) == 0 || len(raw) > limit || strictjson.Scan(ctx, raw, strictjson.Limits{MaxDepth: 16}) != nil {
		return ErrUnavailable
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return ErrUnavailable
	}
	if d.Decode(new(any)) != io.EOF {
		return ErrUnavailable
	}
	return nil
}
func (p *slackFixturePeer) current() bool {
	a, e := time.Parse(time.RFC3339, p.scope.IssuedAt)
	b, f := time.Parse(time.RFC3339, p.scope.ExpiresAt)
	now := p.clock()
	return e == nil && f == nil && !now.Before(a) && now.Before(b) && b.After(a) && b.Sub(a) <= 4*time.Hour && p.ctx.Err() == nil
}
func (p *slackFixturePeer) token(r *http.Request, token []byte) bool {
	return subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), append([]byte("Bearer "), token...)) == 1
}
func (p *slackFixturePeer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !p.current() || r.TLS == nil {
		http.Error(w, "fixture unavailable", 403)
		return
	}
	switch {
	case r.Host == "slack.com" && r.Method == http.MethodPost && r.URL.Path == "/api/apps.connections.open" && r.URL.RawQuery == "":
		if !p.token(r, p.appToken) {
			http.Error(w, "fixture denied", 403)
			return
		}
		var nonce [32]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			http.Error(w, "fixture unavailable", 503)
			return
		}
		ticket := hex.EncodeToString(nonce[:])
		p.mu.Lock()
		for k, v := range p.tickets {
			if !p.clock().Before(v) {
				delete(p.tickets, k)
			}
		}
		if len(p.tickets) >= 4 {
			p.mu.Unlock()
			http.Error(w, "fixture busy", 503)
			return
		}
		p.tickets[ticket] = p.clock().Add(30 * time.Second)
		p.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "url": "wss://wss-native.slack.com/link/?ticket=" + ticket})
	case r.Host == "slack.com" && r.Method == http.MethodPost && r.URL.Path == "/api/chat.postMessage" && r.URL.RawQuery == "":
		if !p.token(r, p.botToken) {
			http.Error(w, "fixture denied", 403)
			return
		}
		p.publish(w, r)
	case r.Host == "wss-native.slack.com" && r.Method == http.MethodGet && r.URL.Path == "/link/":
		query := r.URL.Query()
		ticket := query.Get("ticket")
		p.mu.Lock()
		deadline, ok := p.tickets[ticket]
		delete(p.tickets, ticket)
		p.mu.Unlock()
		if len(query) != 1 || len(query["ticket"]) != 1 || !ok || !p.clock().Before(deadline) {
			http.Error(w, "fixture denied", 403)
			return
		}
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: []string{"wss-native.slack.com"}})
		if err != nil {
			return
		}
		defer conn.CloseNow()
		conn.SetReadLimit(4096)
		ctx, cancel := context.WithCancel(p.ctx)
		defer cancel()
		go func() {
			defer cancel()
			for {
				_, raw, err := conn.Read(ctx)
				if err != nil {
					return
				}
				var ack struct {
					EnvelopeID string `json:"envelope_id"`
				}
				if fixtureDecode(ctx, raw, &ack, 4096) != nil || ack.EnvelopeID == "" {
					return
				}
			}
		}()
		for {
			select {
			case <-ctx.Done():
				return
			case raw := <-p.queue:
				if !p.current() || conn.Write(ctx, websocket.MessageText, raw) != nil {
					return
				}
			}
		}
	default:
		http.NotFound(w, r)
	}
}
func (p *slackFixturePeer) publish(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, (256<<10)+1))
	if err != nil {
		http.Error(w, "fixture denied", 400)
		return
	}
	var post struct {
		Channel string            `json:"channel"`
		Text    string            `json:"text"`
		Blocks  []json.RawMessage `json:"blocks"`
	}
	if fixtureDecode(r.Context(), raw, &post, 256<<10) != nil || post.Channel != p.scope.ChannelID || len(post.Blocks) == 0 || len(post.Blocks) > 16 {
		http.Error(w, "fixture denied", 400)
		return
	}
	var value string
	found := 0
	for _, block := range post.Blocks {
		var v struct {
			Type     string `json:"type"`
			Elements []struct {
				ActionID string `json:"action_id"`
				Value    string `json:"value"`
			} `json:"elements"`
		}
		if json.Unmarshal(block, &v) != nil {
			http.Error(w, "fixture denied", 400)
			return
		}
		if v.Type != "actions" {
			continue
		}
		for _, button := range v.Elements {
			if button.ActionID == p.scope.ApproveActionID {
				found++
				value = button.Value
			}
		}
	}
	var b fixtureActionBinding
	if found != 1 || fixtureDecode(r.Context(), []byte(value), &b, 16384) != nil || len(b.Nonce) < 32 {
		http.Error(w, "fixture denied", 400)
		return
	}
	action, err := p.allowed(b)
	if err != nil {
		http.Error(w, "fixture denied", 403)
		return
	}
	id := hostaction.Digest([]string{b.PlanID, b.PlanDigest, b.Nonce})
	key := b.PlanID + ":" + b.PlanDigest
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.used[key] || len(p.used) >= 64 {
		http.Error(w, "fixture already consumed", 409)
		return
	}
	actionID := p.scope.ApproveActionID
	if action == "reject" {
		actionID = p.scope.RejectActionID
	}
	envelope, _ := json.Marshal(map[string]any{"envelope_id": strings.TrimPrefix(id, "sha256:"), "type": "interactive", "payload": map[string]any{"type": "block_actions", "team": map[string]string{"id": p.scope.WorkspaceID}, "user": map[string]string{"id": p.scope.UserID}, "actions": []map[string]string{{"action_id": actionID, "value": value}}}})
	select {
	case p.queue <- envelope:
		p.used[key] = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	default:
		http.Error(w, "fixture busy", 503)
	}
}
func (p *slackFixturePeer) allowed(b fixtureActionBinding) (string, error) {
	expires, err := time.Parse(time.RFC3339, b.ExpiresAt)
	end, _ := time.Parse(time.RFC3339, p.scope.ExpiresAt)
	if err != nil || !p.clock().Before(expires) || expires.After(end) {
		return "", ErrUnavailable
	}
	if b.PlanID == p.scope.SetupPlanID {
		if b.PlanDigest != p.scope.SetupPlanDigest || b.TargetDigest != p.scope.SetupPlanDigest || b.ReasonDigest != hostaction.BytesDigest([]byte("initialize-local-control-service")) || b.StateRevision != 0 || b.RecoveryEpoch != 0 || b.ExpiresAt != p.setup.ExpiresAt {
			return "", ErrUnavailable
		}
		return "approve", nil
	}
	list, err := p.approvals()
	if err != nil || !exactNativeJSON(generated.SchemaIDNativeSlackFixtureApprovalList, list) {
		return "", ErrUnavailable
	}
	matched := ""
	seen := map[string]bool{}
	for _, a := range list.Approvals {
		key := a.PlanID + ":" + a.PlanDigest
		if seen[key] {
			return "", ErrUnavailable
		}
		seen[key] = true
		if a.PlanID == b.PlanID && a.PlanDigest == b.PlanDigest && a.TargetDigest == b.TargetDigest && a.ReasonDigest == b.ReasonDigest && a.StateRevision == b.StateRevision && a.RecoveryEpoch == b.RecoveryEpoch && a.ExpiresAt == b.ExpiresAt {
			matched = a.Action
		}
	}
	if matched != "approve" && matched != "reject" {
		return "", ErrUnavailable
	}
	return matched, nil
}

package slack

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
)

var messageTimestamp = regexp.MustCompile(`^[0-9]{1,20}\.[0-9]{1,10}$`)

type messageReceipt struct{ Channel, TS, PlanID, Digest, Review, Status string }

// Refresh projects recorded state only. It cannot approve or execute a plan.
// Failed updates remain pending and are retried on the next refresh.
func (t *HTTPTransport) Refresh(ctx context.Context, token []byte, read func(context.Context, string, string) (string, error)) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if time.Now().Before(t.updateRetryAt) {
		return nil
	}
	if t.receipts != nil {
		rows, err := t.receipts.MessageReceipts(ctx)
		if err != nil {
			return err
		}
		for _, r := range rows {
			if r.Destination != t.receiptChannel || !messageTimestamp.MatchString(r.MessageID) {
				continue
			}
			t.messages[r.Destination+":"+r.MessageID] = messageReceipt{Channel: r.Destination, TS: r.MessageID, PlanID: r.PlanID, Digest: r.PlanDigest, Review: r.ReviewText, Status: r.Status}
		}
	}
	var first error
	for key, m := range t.messages {
		state, err := read(ctx, m.PlanID, m.Digest)
		if err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		if state == "pending" || state == m.Status {
			continue
		}
		labels := map[string]string{"approved": "APPROVED — awaiting execution", "succeeded": "APPLIED — execution verified", "rejected": "REJECTED — not executed", "expired": "EXPIRED — approval no longer usable", "stale": "STALE — approval no longer usable", "queued": "APPROVED — execution queued", "running": "APPROVED — execution running", "failed": "EXECUTION FAILED", "partial": "EXECUTION PARTIAL — attention required", "interrupted": "EXECUTION INTERRUPTED", "cancelled": "EXECUTION CANCELLED"}
		label, ok := labels[state]
		if !ok {
			if first == nil {
				first = fmt.Errorf("unknown message state")
			}
			continue
		}
		text := label + "\n\n" + m.Review + "\n\nPlan: " + m.PlanID + "\nDigest: " + m.Digest
		body, _ := json.Marshal(map[string]any{"channel": m.Channel, "ts": m.TS, "text": text, "blocks": []any{}})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://slack.com/api/chat.update", bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+string(token))
		req.Header.Set("Content-Type", "application/json")
		resp, err := t.client.Do(req)
		if err == nil {
			if resp.StatusCode == http.StatusTooManyRequests {
				seconds, parseErr := strconv.ParseInt(resp.Header.Get("Retry-After"), 10, 32)
				if parseErr != nil || seconds <= 0 {
					seconds = 60
				}
				t.updateRetryAt = time.Now().Add(time.Duration(seconds) * time.Second)
				resp.Body.Close()
				return fmt.Errorf("slack update rate limited")
			}
			raw, e := io.ReadAll(io.LimitReader(resp.Body, MaxEnvelopeBytes+1))
			resp.Body.Close()
			var result struct {
				OK bool `json:"ok"`
			}
			if e != nil || resp.StatusCode != http.StatusOK || len(raw) > MaxEnvelopeBytes || decodeProvider(ctx, raw, &result, MaxEnvelopeBytes) != nil || !result.OK {
				err = fmt.Errorf("slack update unavailable")
			}
		}
		if err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		if t.receipts != nil {
			if err := t.receipts.CompleteMessageReceipt(ctx, m.Channel, m.TS, state); err != nil {
				if first == nil {
					first = err
				}
				continue
			}
		}
		m.Status = state
		t.messages[key] = m
		switch state {
		case "succeeded", "rejected", "expired", "stale", "failed", "partial", "cancelled":
			delete(t.messages, key)
		}
	}
	return first
}

// SetReceiptRepository is configured before the server starts publishing.
func (t *HTTPTransport) SetReceiptRepository(repo acknowledgement.MessageReceiptRepository, channel string) {
	t.receipts = repo
	t.receiptChannel = channel
}

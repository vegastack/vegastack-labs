package slack

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/coder/websocket"
	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

const (
	slackConnectionsOpenURL = "https://slack.com/api/apps.connections.open"
	slackPostMessageURL     = "https://slack.com/api/chat.postMessage"
)

var dynamicSlackSocketHost = regexp.MustCompile(`^wss-[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.slack\.com$`)

type HTTPTransport struct {
	client *http.Client
}

func NewHTTPTransport(client *http.Client) (*HTTPTransport, error) {
	if client == nil || client.Timeout <= 0 || client.Timeout > 30*time.Second {
		return nil, slackError(generated.ErrorCodeInputInvalid, "slack-http", false)
	}
	// Refuse every redirect so an Authorization header and an approval card can
	// never be replayed to an endpoint selected by a provider response.
	boundedClient := *client
	boundedClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &HTTPTransport{client: &boundedClient}, nil
}

func (transport *HTTPTransport) Open(ctx context.Context, appToken []byte) (Socket, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, slackConnectionsOpenURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+string(appToken))
	response, err := transport.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("slack connections response")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 16<<10))
	if err != nil || len(body) >= 16<<10 {
		return nil, fmt.Errorf("slack connections response")
	}
	var result struct {
		OK  bool   `json:"ok"`
		URL string `json:"url"`
	}
	if decodeClosed(body, &result) != nil || !result.OK || !transport.allowedSocketURL(result.URL) {
		return nil, fmt.Errorf("slack connections response")
	}
	connection, _, err := websocket.Dial(ctx, result.URL, &websocket.DialOptions{HTTPClient: transport.client})
	if err != nil {
		return nil, err
	}
	connection.SetReadLimit(MaxEnvelopeBytes)
	return &websocketSocket{connection: connection}, nil
}

func (transport *HTTPTransport) Publish(ctx context.Context, botToken []byte, channel, approveActionID, rejectActionID string, card acknowledgement.RequestCard) error {
	value, err := json.Marshal(actionBinding{PlanID: card.Request.PlanID, PlanDigest: card.Request.PlanDigest, TargetDigest: card.Request.TargetDigest, ReasonDigest: card.Request.ReasonDigest, Nonce: card.Nonce, StateRevision: card.Request.StateRevision, RecoveryEpoch: card.Request.RecoveryEpoch, ExpiresAt: card.Request.ExpiresAt})
	if err != nil {
		return err
	}
	payload := map[string]any{
		"channel": channel,
		"text":    "VegaStack plan acknowledgement required",
		"blocks": []any{map[string]any{"type": "actions", "elements": []any{
			map[string]any{"type": "button", "text": map[string]string{"type": "plain_text", "text": "Approve"}, "style": "primary", "action_id": approveActionID, "value": string(value)},
			map[string]any{"type": "button", "text": map[string]string{"type": "plain_text", "text": "Reject"}, "style": "danger", "action_id": rejectActionID, "value": string(value)},
		}}},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, slackPostMessageURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+string(botToken))
	request.Header.Set("Content-Type", "application/json")
	response, err := transport.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	result, err := io.ReadAll(io.LimitReader(response.Body, 16<<10))
	if err != nil || len(result) >= 16<<10 || response.StatusCode != http.StatusOK {
		return fmt.Errorf("slack publish response")
	}
	var status struct {
		OK bool `json:"ok"`
	}
	if decodeClosed(result, &status) != nil || !status.OK {
		return fmt.Errorf("slack publish response")
	}
	return nil
}

func (transport *HTTPTransport) allowedSocketURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "wss" || parsed.User != nil || parsed.Fragment != "" {
		return false
	}
	if parsed.Port() != "" || parsed.Path != "/link/" || parsed.RawPath != "" || parsed.ForceQuery {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	if host != "wss.slack.com" && host != "wss-primary.slack.com" && !dynamicSlackSocketHost.MatchString(host) {
		return false
	}
	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil || len(query) < 1 || len(query) > 2 || len(query["ticket"]) != 1 || !boundedSocketParameter(query["ticket"][0], 4096) {
		return false
	}
	for key, values := range query {
		if key != "ticket" && key != "app_id" {
			return false
		}
		if len(values) != 1 || !boundedSocketParameter(values[0], 256) {
			return false
		}
	}
	return true
}

func boundedSocketParameter(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

type websocketSocket struct{ connection *websocket.Conn }

func (socket *websocketSocket) Receive(ctx context.Context) ([]byte, error) {
	messageType, payload, err := socket.connection.Read(ctx)
	if err != nil {
		return nil, err
	}
	if messageType != websocket.MessageText || len(payload) > MaxEnvelopeBytes {
		return nil, fmt.Errorf("slack envelope")
	}
	return payload, nil
}

func (socket *websocketSocket) Acknowledge(ctx context.Context, envelopeID string) error {
	payload, err := json.Marshal(map[string]string{"envelope_id": envelopeID})
	if err != nil {
		return err
	}
	return socket.connection.Write(ctx, websocket.MessageText, payload)
}

func (socket *websocketSocket) Close() error {
	return socket.connection.Close(websocket.StatusNormalClosure, "")
}

package coolify

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"io"
	"net/http"
	"regexp"
	"sync"
	"unicode/utf8"
)

type EnvironmentValue struct {
	Name  string
	Value *credentialref.Value
}

var environmentName = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)

// applyEnvironment uses the pinned PATCH endpoint. Its response can contain
// plaintext values, so it is bounded and discarded without decoding or logging.
func (c *Client) applyEnvironment(ctx context.Context, app string, values []EnvironmentValue, token *credentialref.Value, check func() error) error {
	if len(values) > 32 {
		return ErrInput
	}
	seen := map[string]bool{}
	for _, v := range values {
		if !environmentName.MatchString(v.Name) || seen[v.Name] || v.Value == nil || len(v.Value.Bytes()) == 0 || len(v.Value.Bytes()) > 16384 || !utf8.Valid(v.Value.Bytes()) || bytes.IndexByte(v.Value.Bytes(), 0) >= 0 {
			return ErrInput
		}
		seen[v.Name] = true
	}
	for _, v := range values {
		if e := check(); e != nil {
			return e
		}
		body, e := json.Marshal(struct {
			Key       string `json:"key"`
			Value     string `json:"value"`
			Preview   bool   `json:"is_preview"`
			Literal   bool   `json:"is_literal"`
			Multiline bool   `json:"is_multiline"`
			ShownOnce bool   `json:"is_shown_once"`
		}{v.Name, string(v.Value.Bytes()), false, true, true, true})
		if e != nil {
			return ErrInput
		}
		req, e := http.NewRequestWithContext(ctx, http.MethodPatch, c.base+"/applications/"+app+"/envs", &environmentBody{bytes: body})
		if e != nil {
			clear(body)
			return ErrInput
		}
		req.ContentLength = int64(len(body))
		req.Header.Set("Authorization", "Bearer "+string(token.Bytes()))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		response, e := c.http.Do(req)
		_ = req.Body.Close()
		if e != nil {
			return ErrUnavailable
		}
		n, copyErr := io.Copy(io.Discard, io.LimitReader(response.Body, maxBody+1))
		_ = response.Body.Close()
		if response.StatusCode != http.StatusCreated || copyErr != nil || n > maxBody {
			return ErrUnavailable
		}
		if e = check(); e != nil {
			return e
		}
	}
	return nil
}

// The transport may finish request writes after an early provider response.
// Synchronize clearing with Read instead of racing a byte-slice overwrite.
type environmentBody struct {
	mu     sync.Mutex
	bytes  []byte
	offset int
}

func (b *environmentBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.offset >= len(b.bytes) {
		return 0, io.EOF
	}
	n := copy(p, b.bytes[b.offset:])
	b.offset += n
	return n, nil
}
func (b *environmentBody) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	clear(b.bytes)
	b.bytes = nil
	return nil
}

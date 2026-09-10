package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/store"
)

const CursorLifetime = 15 * time.Minute

type CursorBinding struct {
	SchemaMajor   int
	EndpointID    string
	QueryDigest   string
	ScopeDigest   string
	GrantRevision int64
	Snapshot      store.RevisionToken
	EvaluationAt  time.Time
}

type CursorPosition struct {
	SortValues  []string
	ImmutableID string
}
type DecodedCursor struct {
	Position     CursorPosition
	Snapshot     store.RevisionToken
	EvaluationAt time.Time
}
type CursorCodec interface {
	Encode(CursorBinding, CursorPosition) (string, error)
	Decode(string, CursorBinding) (DecodedCursor, error)
	Now() time.Time
}

type cursorCodec struct {
	key [32]byte
	now func() time.Time
}
type cursorPayload struct {
	Version       int      `json:"v"`
	SchemaMajor   int      `json:"m"`
	EndpointID    string   `json:"e"`
	QueryDigest   string   `json:"q"`
	ScopeDigest   string   `json:"s"`
	GrantRevision int64    `json:"g"`
	StateRevision int64    `json:"r"`
	RecoveryEpoch int64    `json:"p"`
	SortValues    []string `json:"o"`
	ImmutableID   string   `json:"i"`
	ExpiresAt     int64    `json:"x"`
	EvaluationAt  string   `json:"a,omitempty"`
}

func NewCursorCodec(random io.Reader, now func() time.Time) (CursorCodec, error) {
	if random == nil || now == nil {
		return nil, failure.New("DEPENDENCY_UNAVAILABLE", "cursor-key", false)
	}
	codec := &cursorCodec{now: now}
	if _, err := io.ReadFull(random, codec.key[:]); err != nil {
		return nil, failure.New("DEPENDENCY_UNAVAILABLE", "cursor-key", false)
	}
	return codec, nil
}

func (codec *cursorCodec) Encode(binding CursorBinding, position CursorPosition) (string, error) {
	if !validCursorBinding(binding) || len(position.SortValues) == 0 || len(position.SortValues) > 4 || position.ImmutableID == "" || len(position.ImmutableID) > 256 {
		return "", failure.New("STATE_CONFLICT", "cursor", false)
	}
	payload := cursorPayload{Version: 1, SchemaMajor: binding.SchemaMajor, EndpointID: binding.EndpointID, QueryDigest: binding.QueryDigest, ScopeDigest: binding.ScopeDigest, GrantRevision: binding.GrantRevision, StateRevision: binding.Snapshot.StateRevision, RecoveryEpoch: binding.Snapshot.RecoveryEpoch, SortValues: append([]string(nil), position.SortValues...), ImmutableID: position.ImmutableID, ExpiresAt: codec.Now().Add(CursorLifetime).Unix()}
	if !binding.EvaluationAt.IsZero() {
		payload.EvaluationAt = binding.EvaluationAt.UTC().Format(time.RFC3339Nano)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", failure.New("STATE_CONFLICT", "cursor", false)
	}
	mac := hmac.New(sha256.New, codec.key[:])
	_, _ = mac.Write(body)
	token := base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if len(token) > MaxCursorBytes {
		return "", failure.New("STATE_CONFLICT", "cursor", false)
	}
	return token, nil
}

func (codec *cursorCodec) Decode(token string, binding CursorBinding) (DecodedCursor, error) {
	conflict := func() (DecodedCursor, error) { return DecodedCursor{}, failure.New("STATE_CONFLICT", "cursor", false) }
	if codec == nil || token == "" || len(token) > MaxCursorBytes || !validCursorBinding(binding) {
		return conflict()
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return conflict()
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(body) == 0 || len(body) > 1536 {
		return conflict()
	}
	wantMAC, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(wantMAC) != sha256.Size {
		return conflict()
	}
	mac := hmac.New(sha256.New, codec.key[:])
	_, _ = mac.Write(body)
	if !hmac.Equal(wantMAC, mac.Sum(nil)) {
		return conflict()
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	var payload cursorPayload
	if err := decoder.Decode(&payload); err != nil {
		return conflict()
	}
	var evaluationAt time.Time
	if payload.EvaluationAt != "" {
		evaluationAt, err = time.Parse(time.RFC3339Nano, payload.EvaluationAt)
		if err != nil || payload.EvaluationAt != evaluationAt.UTC().Format(time.RFC3339Nano) {
			return conflict()
		}
	}
	wildcardSnapshot := binding.Snapshot.StateRevision == -1 && binding.Snapshot.RecoveryEpoch == -1
	if payload.Version != 1 || payload.SchemaMajor != binding.SchemaMajor || payload.EndpointID != binding.EndpointID || payload.QueryDigest != binding.QueryDigest || payload.ScopeDigest != binding.ScopeDigest || payload.GrantRevision != binding.GrantRevision || (!wildcardSnapshot && (payload.StateRevision != binding.Snapshot.StateRevision || payload.RecoveryEpoch != binding.Snapshot.RecoveryEpoch)) || (!binding.EvaluationAt.IsZero() && !evaluationAt.Equal(binding.EvaluationAt)) || codec.Now().Unix() > payload.ExpiresAt || len(payload.SortValues) == 0 || len(payload.SortValues) > 4 || payload.ImmutableID == "" {
		return conflict()
	}
	return DecodedCursor{Position: CursorPosition{SortValues: append([]string(nil), payload.SortValues...), ImmutableID: payload.ImmutableID}, Snapshot: store.RevisionToken{StateRevision: payload.StateRevision, RecoveryEpoch: payload.RecoveryEpoch}, EvaluationAt: evaluationAt}, nil
}

func (codec *cursorCodec) Now() time.Time {
	if codec == nil || codec.now == nil {
		return time.Time{}
	}
	return codec.now().UTC()
}

func validCursorBinding(binding CursorBinding) bool {
	wildcard := binding.Snapshot.StateRevision == -1 && binding.Snapshot.RecoveryEpoch == -1
	return binding.SchemaMajor == 1 && binding.EndpointID != "" && len(binding.EndpointID) <= 128 && binding.QueryDigest != "" && len(binding.QueryDigest) <= 128 && binding.ScopeDigest != "" && len(binding.ScopeDigest) <= 128 && binding.GrantRevision > 0 && ((binding.Snapshot.StateRevision >= 0 && binding.Snapshot.RecoveryEpoch >= 0) || wildcard)
}

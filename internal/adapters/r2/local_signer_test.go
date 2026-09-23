package r2

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
)

func TestLocalSignerCreatesExactR2JWTAndRejectsExpandedParentShape(t *testing.T) {
	now := time.Date(2026, 9, 23, 18, 0, 0, 0, time.UTC)
	signer := LocalSigner{Endpoint: "https://account.r2.cloudflarestorage.com", Bucket: "bucket-a", Clock: func() time.Time { return now }}
	request := adapter.SessionRequest{Prefix: "critical/generation-a/", Actions: []string{"DeleteObject", "GetObject", "ListObjectsV2", "PutObject"}, TTL: 5 * time.Minute}
	parent := []byte(`{"accountId":"account","accessKeyId":"key","secretAccessKey":"secret"}`)
	session, err := signer.SignScopedSession(context.Background(), parent, request)
	if err != nil {
		t.Fatal(err)
	}
	token, err := base64.StdEncoding.DecodeString(string(session.SessionToken))
	if err != nil || !strings.HasPrefix(string(token), "jwt/") || string(session.AccessKeyID) != "key" || len(session.SecretAccessKey) != 64 || !session.ExpiresAt.Equal(now.Add(5*time.Minute)) {
		t.Fatalf("session shape invalid: token=%q expiry=%s err=%v", token, session.ExpiresAt, err)
	}
	if _, err := signer.SignScopedSession(context.Background(), []byte(`{"accountId":"account","accessKeyId":"key","secretAccessKey":"secret","adminToken":"too-wide"}`), request); err == nil {
		t.Fatal("expanded parent secret shape accepted")
	}
}

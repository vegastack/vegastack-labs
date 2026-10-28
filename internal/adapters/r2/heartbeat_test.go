package r2

import (
	"context"
	"errors"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/siteheartbeat"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type heartbeatResolver struct {
	ref      credentialref.Reference
	resolved int
	value    *credentialref.Value
	err      error
}

func (r *heartbeatResolver) Inspect(context.Context, credentialref.Reference) (credentialref.Metadata, error) {
	return credentialref.Metadata{Reference: r.ref, MaterialVersion: "version-a", State: credentialref.Current}, nil
}
func (r *heartbeatResolver) Resolve(context.Context, credentialref.Reference) (*credentialref.Value, error) {
	r.resolved++
	r.value, _ = credentialref.NewValue([]byte(`{"accessKeyId":"access","secretAccessKey":"secret-private-canary","sessionToken":"limited-session"}`))
	return r.value, r.err
}

type heartbeatTransport func(*http.Request) (*http.Response, error)

func (f heartbeatTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestHeartbeatWriterUsesOnlyExactSignedPUTAndWipesResolvedCredential(t *testing.T) {
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	digest := "sha256:" + strings.Repeat("a", 64)
	payload, _ := siteheartbeat.Encode(siteheartbeat.Snapshot{SiteDigest: digest, ObservedAt: now}, now)
	resolver := &heartbeatResolver{ref: credentialref.Reference{ID: "heartbeat-credential", Consumer: HeartbeatConsumer}}
	calls := 0
	w := HeartbeatWriter{Client: S3Client{Endpoint: "https://account.r2.cloudflarestorage.com", Bucket: "status-bucket", Clock: func() time.Time { return now }, Client: &http.Client{Transport: heartbeatTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		body, _ := io.ReadAll(r.Body)
		if r.Method != "PUT" || r.URL.Path != "/status-bucket/heartbeat.json" || string(body) != string(payload) || r.Header.Get("x-amz-security-token") != "limited-session" || !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			t.Fatal("wrong exact PUT")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
	})}}, ObjectKey: "heartbeat.json", BackupBucket: "backup-bucket", SiteDigest: digest, Reference: resolver.ref, Resolver: resolver}
	if err := w.WriteHeartbeat(context.Background(), payload); err != nil || calls != 1 || len(resolver.value.Bytes()) != 0 {
		t.Fatal(err, calls)
	}
	w.Reference.Consumer = "backup-writer"
	if w.WriteHeartbeat(context.Background(), payload) == nil || calls != 1 {
		t.Fatal("wrong purpose reached provider")
	}
	w.Reference = resolver.ref
	w.Client.Bucket = w.BackupBucket
	if w.WriteHeartbeat(context.Background(), payload) == nil || calls != 1 {
		t.Fatal("backup bucket reached provider")
	}
	w.Client.Bucket = "status-bucket"
	w.Client.Client.Transport = heartbeatTransport(func(*http.Request) (*http.Response, error) { return nil, errors.New("secret-private-canary") })
	if err := w.WriteHeartbeat(context.Background(), payload); err == nil || strings.Contains(err.Error(), "secret-private-canary") {
		t.Fatal("raw provider error leaked")
	}
	w.Client.Client.Transport = heartbeatTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 403, Body: io.NopCloser(strings.NewReader("private-provider-denial")), Header: http.Header{}}, nil
	})
	if err := w.WriteHeartbeat(context.Background(), payload); err == nil || strings.Contains(err.Error(), "private-provider-denial") {
		t.Fatal("denied write accepted or leaked")
	}
	resolver.err = errors.New("private-resolver-error")
	if err := w.WriteHeartbeat(context.Background(), payload); err == nil || len(resolver.value.Bytes()) != 0 || strings.Contains(err.Error(), "private-resolver-error") {
		t.Fatal("partial resolved credential retained")
	}
}
func TestHeartbeatWriterRejectsUnknownSecretFieldsBeforeResolving(t *testing.T) {
	r := &heartbeatResolver{}
	w := HeartbeatWriter{Client: S3Client{Endpoint: "https://account.r2.cloudflarestorage.com", Bucket: "status-bucket"}, ObjectKey: "heartbeat.json", Resolver: r}
	if w.WriteHeartbeat(context.Background(), []byte(`{"secret":"private-canary"}`)) == nil || r.resolved != 0 {
		t.Fatal("unsafe payload reached resolver")
	}
}

//go:build linux

package r2

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/backup"
)

func TestQualifiedCutoffExecutesExpiredWriterProbesAndCleansArtifacts(t *testing.T) {
	var cleanups atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodPost && request.URL.Query().Has("uploads"):
			writer.Header().Set("Content-Type", "application/xml")
			_, _ = writer.Write([]byte(`<InitiateMultipartUploadResult><UploadId>upload-a</UploadId></InitiateMultipartUploadResult>`))
		case request.Method == http.MethodPut:
			http.Error(writer, "expired", http.StatusForbidden)
		case request.Method == http.MethodPost && request.URL.Query().Get("uploadId") == "upload-a":
			http.Error(writer, "expired", http.StatusForbidden)
		case request.Method == http.MethodDelete:
			cleanups.Add(1)
			writer.WriteHeader(http.StatusNoContent)
		default:
			http.Error(writer, "unexpected", http.StatusBadRequest)
		}
	}))
	defer server.Close()
	now := time.Now().UTC()
	probe := &qualifiedCutoff{s3: S3Client{Endpoint: server.URL, Bucket: "bucket-a", Client: server.Client()}, clock: time.Now, deadline: now.Add(time.Minute), key: "critical/gen-a/locks/cutoff-a",
		issued: S3Credentials{AccessKeyID: "expired-access", SecretAccessKey: "expired-secret", SessionToken: "expired-token"}, cleanup: S3Credentials{AccessKeyID: "parent-access", SecretAccessKey: "parent-secret"}}
	pending := backup.PendingOffsiteGeneration{SessionExpiries: []time.Time{now.Add(-time.Second)}}
	if _, err := probe.AwaitWriterCutoff(context.Background(), pending); err != nil {
		t.Fatal(err)
	}
	if denied, err := probe.DenyNewPUT(context.Background(), "gen-a"); err != nil || !denied {
		t.Fatalf("expired PUT denial = %v, %v", denied, err)
	}
	if denied, err := probe.DenyMultipartCompletion(context.Background(), "gen-a"); err != nil || !denied {
		t.Fatalf("expired multipart denial = %v, %v", denied, err)
	}
	if cleanups.Load() != 2 {
		t.Fatalf("cleanup calls = %d", cleanups.Load())
	}
}

func TestQualifiedCutoffRejectsAcceptedExpiredPUT(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPut {
			writer.WriteHeader(http.StatusOK)
			return
		}
		if request.Method == http.MethodDelete {
			writer.WriteHeader(http.StatusNoContent)
			return
		}
		http.Error(writer, "unexpected", http.StatusBadRequest)
	}))
	defer server.Close()
	probe := &qualifiedCutoff{s3: S3Client{Endpoint: server.URL, Bucket: "bucket-a", Client: server.Client()}, deadline: time.Now().Add(time.Minute), key: "critical/gen-a/locks/cutoff-a",
		issued: S3Credentials{AccessKeyID: "expired-access", SecretAccessKey: "expired-secret", SessionToken: "expired-token"}, cleanup: S3Credentials{AccessKeyID: "parent-access", SecretAccessKey: "parent-secret"}}
	if denied, err := probe.DenyNewPUT(context.Background(), "gen-a"); err != nil || denied {
		t.Fatalf("accepted expired PUT treated as denied: %v, %v", denied, err)
	}
}

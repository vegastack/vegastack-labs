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
		issued: S3Credentials{AccessKeyID: []byte("expired-access"), SecretAccessKey: []byte("expired-secret"), SessionToken: []byte("expired-token")}, cleanup: S3Credentials{AccessKeyID: []byte("parent-access"), SecretAccessKey: []byte("parent-secret")}}
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
	if err := probe.CleanupWriterProbes(context.Background()); err != nil {
		t.Fatal(err)
	}
	if cleanups.Load() != 2 {
		t.Fatalf("cleanup calls = %d", cleanups.Load())
	}
}

func TestQualifiedCutoffCleanupAttemptsObjectAndMultipartAfterCancellationAndErrors(t *testing.T) {
	var deleteObject, abortMultipart atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodPost && request.URL.Query().Has("uploads"):
			writer.Header().Set("Content-Type", "application/xml")
			_, _ = writer.Write([]byte(`<InitiateMultipartUploadResult><UploadId>upload-cancelled</UploadId></InitiateMultipartUploadResult>`))
		case request.Method == http.MethodDelete && request.URL.Query().Get("uploadId") != "":
			abortMultipart.Add(1)
			http.Error(writer, "cleanup failed", http.StatusInternalServerError)
		case request.Method == http.MethodDelete:
			deleteObject.Add(1)
			http.Error(writer, "cleanup failed", http.StatusInternalServerError)
		default:
			http.Error(writer, "unexpected", http.StatusBadRequest)
		}
	}))
	defer server.Close()
	now := time.Now().UTC()
	probe := &qualifiedCutoff{s3: S3Client{Endpoint: server.URL, Bucket: "bucket-a", Client: server.Client()}, clock: time.Now, deadline: now.Add(time.Minute), key: "critical/gen-a/locks/cutoff-a",
		issued: S3Credentials{AccessKeyID: []byte("writer"), SecretAccessKey: []byte("writer-secret"), SessionToken: []byte("writer-token")}, cleanup: S3Credentials{AccessKeyID: []byte("parent"), SecretAccessKey: []byte("parent-secret")}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Initiation needs a live context; cancel only after the provider accepted it.
	ctx, cancel = context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	if _, err := probe.AwaitWriterCutoff(ctx, backup.PendingOffsiteGeneration{SessionExpiries: []time.Time{now.Add(time.Second)}}); err == nil {
		t.Fatal("cancelled expiry wait succeeded")
	}
	if err := probe.CleanupWriterProbes(ctx); err == nil {
		t.Fatal("provider cleanup errors were hidden")
	}
	if deleteObject.Load() != 1 || abortMultipart.Load() != 1 {
		t.Fatalf("cleanup calls object=%d multipart=%d", deleteObject.Load(), abortMultipart.Load())
	}
	_, cleanup, uploadID := probe.credentials()
	if len(cleanup.AccessKeyID) != 0 || uploadID != "" {
		t.Fatal("cleanup material retained after attempts completed")
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
		issued: S3Credentials{AccessKeyID: []byte("expired-access"), SecretAccessKey: []byte("expired-secret"), SessionToken: []byte("expired-token")}, cleanup: S3Credentials{AccessKeyID: []byte("parent-access"), SecretAccessKey: []byte("parent-secret")}}
	if denied, err := probe.DenyNewPUT(context.Background(), "gen-a"); err != nil || denied {
		t.Fatalf("accepted expired PUT treated as denied: %v, %v", denied, err)
	}
}

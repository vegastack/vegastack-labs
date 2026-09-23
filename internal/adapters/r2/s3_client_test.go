package r2

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestS3InventoryPaginatesAndHashesFullObjects(t *testing.T) {
	objects := map[string]string{"critical/gen-a/config": "config-body", "critical/gen-a/data/one": "object-body"}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !strings.HasPrefix(request.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") || request.Header.Get("x-amz-security-token") != "session-token" {
			t.Fatal("request was not signed with the scoped session")
		}
		if request.URL.Path == "/bucket-a" {
			writer.Header().Set("Content-Type", "application/xml")
			if request.URL.Query().Get("continuation-token") == "" {
				_, _ = fmt.Fprintf(writer, `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><IsTruncated>true</IsTruncated><NextContinuationToken>page-2</NextContinuationToken><Contents><Key>critical/gen-a/config</Key><Size>%d</Size></Contents></ListBucketResult>`, len(objects["critical/gen-a/config"]))
				return
			}
			_, _ = fmt.Fprintf(writer, `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><IsTruncated>false</IsTruncated><Contents><Key>critical/gen-a/data/one</Key><Size>%d</Size></Contents></ListBucketResult>`, len(objects["critical/gen-a/data/one"]))
			return
		}
		body, exists := objects[strings.TrimPrefix(request.URL.Path, "/bucket-a/")]
		if !exists {
			http.NotFound(writer, request)
			return
		}
		_, _ = writer.Write([]byte(body))
	}))
	defer server.Close()

	client := S3Client{Endpoint: server.URL, Bucket: "bucket-a", Client: server.Client(), Clock: func() time.Time { return time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC) }}
	observation, err := client.Inventory(context.Background(), "critical/gen-a/", S3Credentials{AccessKeyID: []byte("access"), SecretAccessKey: []byte("secret"), SessionToken: []byte("session-token")}, 3, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(observation.Objects) != 2 || observation.ObjectCount != 2 || observation.ObjectBytes != int64(len(objects["critical/gen-a/config"])+len(objects["critical/gen-a/data/one"])) {
		t.Fatalf("unexpected inventory: %+v", observation)
	}
	digest := sha256.Sum256([]byte(objects["critical/gen-a/config"]))
	if observation.Objects[0].Key != "config" || observation.Objects[0].Digest != "sha256:"+hex.EncodeToString(digest[:]) {
		t.Fatalf("full object digest not recorded: %+v", observation.Objects[0])
	}
}

func TestS3InventoryRejectsProviderObjectOutsideRequestedGeneration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(`<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>critical/other/config</Key><Size>1</Size></Contents></ListBucketResult>`))
	}))
	defer server.Close()
	_, err := (S3Client{Endpoint: server.URL, Bucket: "bucket-a", Client: server.Client()}).Inventory(context.Background(), "critical/gen-a/", S3Credentials{AccessKeyID: []byte("access"), SecretAccessKey: []byte("secret")}, 2, 10)
	if err == nil {
		t.Fatal("cross-generation object accepted")
	}
}

func TestS3ListMultipartUploadsPaginatesAndReturnsOnlyExactKey(t *testing.T) {
	key := "critical/gen-a/locks/cutoff-a"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || !request.URL.Query().Has("uploads") || request.URL.Query().Get("prefix") != key {
			http.Error(writer, "unexpected", http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "application/xml")
		if request.URL.Query().Get("key-marker") == "" {
			_, _ = fmt.Fprintf(writer, `<ListMultipartUploadsResult><IsTruncated>true</IsTruncated><NextKeyMarker>%s</NextKeyMarker><NextUploadIdMarker>marker-a</NextUploadIdMarker><Upload><Key>%s</Key><UploadId>upload-b</UploadId></Upload><Upload><Key>%s-neighbor</Key><UploadId>do-not-abort</UploadId></Upload></ListMultipartUploadsResult>`, key, key, key)
			return
		}
		_, _ = fmt.Fprintf(writer, `<ListMultipartUploadsResult><IsTruncated>false</IsTruncated><Upload><Key>%s</Key><UploadId>upload-a</UploadId></Upload></ListMultipartUploadsResult>`, key)
	}))
	defer server.Close()
	client := S3Client{Endpoint: server.URL, Bucket: "bucket-a", Client: server.Client()}
	uploads, err := client.ListMultipartUploads(context.Background(), key, S3Credentials{AccessKeyID: []byte("access"), SecretAccessKey: []byte("secret")})
	if err != nil || strings.Join(uploads, ",") != "upload-a,upload-b" {
		t.Fatalf("exact uploads = %v, %v", uploads, err)
	}
}

func TestS3ListMultipartUploadsRejectsDuplicateExactCandidate(t *testing.T) {
	key := "critical/gen-a/locks/cutoff-a"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(writer, `<ListMultipartUploadsResult><IsTruncated>false</IsTruncated><Upload><Key>%s</Key><UploadId>duplicate</UploadId></Upload><Upload><Key>%s</Key><UploadId>duplicate</UploadId></Upload></ListMultipartUploadsResult>`, key, key)
	}))
	defer server.Close()
	_, err := (S3Client{Endpoint: server.URL, Bucket: "bucket-a", Client: server.Client()}).ListMultipartUploads(context.Background(), key, S3Credentials{AccessKeyID: []byte("access"), SecretAccessKey: []byte("secret")})
	if err == nil {
		t.Fatal("ambiguous duplicate upload accepted")
	}
}

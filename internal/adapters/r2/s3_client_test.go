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
	observation, err := client.Inventory(context.Background(), "critical/gen-a/", S3Credentials{AccessKeyID: "access", SecretAccessKey: "secret", SessionToken: "session-token"}, 3, 100)
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
	_, err := (S3Client{Endpoint: server.URL, Bucket: "bucket-a", Client: server.Client()}).Inventory(context.Background(), "critical/gen-a/", S3Credentials{AccessKeyID: "access", SecretAccessKey: "secret"}, 2, 10)
	if err == nil {
		t.Fatal("cross-generation object accepted")
	}
}

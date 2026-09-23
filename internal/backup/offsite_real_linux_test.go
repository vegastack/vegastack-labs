//go:build linux

package backup

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
)

// TestPinnedResticOffsiteS3IAM is the Linux acceptance lane for Task 4. It
// uses the official digest-pinned binary against an in-memory S3-compatible
// endpoint and the real one-run IAM handler. The fixture proves restic reaches
// IAM without static credentials, creates one independent v2 repository,
// lists the exact snapshot, reads all payload, and restores it.
func TestPinnedResticOffsiteS3IAM(t *testing.T) {
	binary := os.Getenv("VSK_RESTIC_0191_BINARY")
	if binary == "" {
		t.Skip("official pinned restic 0.19.1 binary not provided")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	storage := newHermeticS3(t)
	defer storage.server.Close()

	now := time.Now().UTC()
	parent, err := credentialref.NewValue([]byte("fixture-parent-signing-material"))
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	binding := adapter.SessionRequest{RunID: "run-offsite-real", StepID: "step-offsite-real", PointID: "point-offsite-real", GenerationID: "generation-offsite-real", RecoveryEpoch: 1, Prefix: "generation-offsite-real/", Actions: []string{"ListBucket", "PutObject", "GetObject", "DeleteObject"}, Deadline: now.Add(5 * time.Minute), TTL: 2 * time.Minute}
	bearer := []byte("0123456789abcdef0123456789abcdef")
	endpoint, err := NewOneRunEndpoint(OneRunConfig{Issuer: issuerFixture{now: now}, Parent: parent, Request: binding, Bearer: bearer, Path: OneRunIAMPath(binding), Clock: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Close()
	iam := httptest.NewServer(endpoint)
	defer iam.Close()

	passwordFile, err := sealedPasswordFile([]byte("offsite-real-fixture-password"))
	if err != nil {
		t.Fatal(err)
	}
	defer passwordFile.Close()
	authorization := append([]byte("Bearer "), bearer...)
	bearerFile, err := SealedBearerFile(authorization)
	for index := range authorization {
		authorization[index] = 0
	}
	if err != nil {
		t.Fatal(err)
	}
	defer bearerFile.Close()
	runner := &resticRunner{clock: time.Now}
	binaryFile, err := runner.verifyBinary(ResticRequest{BinaryPath: binary, Architecture: runtime.GOARCH})
	if err != nil {
		t.Fatal(err)
	}
	defer binaryFile.Close()
	repositoryURL := "s3:" + storage.server.URL + "/bucket/generation-offsite-real"
	environment := []string{"HOME=/nonexistent", "RESTIC_PASSWORD_FILE=/proc/self/fd/3", "AWS_CONTAINER_CREDENTIALS_FULL_URI=" + iam.URL + OneRunIAMPath(binding), "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE=/proc/self/fd/4"}
	run := func(arguments ...string) []byte {
		t.Helper()
		for _, file := range []*os.File{passwordFile, bearerFile, binaryFile} {
			if _, err := file.Seek(0, io.SeekStart); err != nil {
				t.Fatal(err)
			}
		}
		command := exec.CommandContext(ctx, "/proc/self/fd/5", arguments...)
		command.Args[0] = binary
		command.ExtraFiles = []*os.File{passwordFile, bearerFile, binaryFile}
		command.Env = environment
		var stdout, stderr bytes.Buffer
		command.Stdout, command.Stderr = &stdout, &stderr
		if err := command.Run(); err != nil {
			t.Fatalf("restic %v: %v stderr=%q", arguments, err, stderr.String())
		}
		if strings.Contains(stdout.String()+stderr.String(), string(bearer)) || strings.Contains(stdout.String()+stderr.String(), "fixture-parent-signing-material") {
			t.Fatal("credential material escaped child output")
		}
		return stdout.Bytes()
	}
	common := []string{"-r", repositoryURL, "--json", "--no-cache", "--password-file", "/proc/self/fd/3"}
	run(append(append([]string{}, common...), "init", "--repository-version", "2")...)
	snapshot := filepath.Join(t.TempDir(), "snapshot.sqlite")
	if err := os.WriteFile(snapshot, []byte(strings.Repeat("captured-sqlite-page", 4096)), 0o600); err != nil {
		t.Fatal(err)
	}
	backupOutput := run(append(append([]string{}, common...), "backup", snapshot, "--host", "vsk-labs")...)
	summary, err := parseResticSummary(backupOutput)
	if err != nil || !validObjectName(summary.SnapshotID) {
		t.Fatalf("backup summary: %#v %v", summary, err)
	}
	snapshotsOutput := run(append(append([]string{}, common...), "snapshots")...)
	snapshotIDs, err := parseResticSnapshots(snapshotsOutput)
	if err != nil || len(snapshotIDs) != 1 || snapshotIDs[0] != summary.SnapshotID {
		t.Fatalf("snapshots = %#v, %v", snapshotIDs, err)
	}
	run(append(append([]string{}, common...), "check", "--read-data")...)
	restore := filepath.Join(t.TempDir(), "restore")
	if err := os.Mkdir(restore, 0o700); err != nil {
		t.Fatal(err)
	}
	run(append(append([]string{}, common...), "restore", summary.SnapshotID, "--target", restore)...)
	if atomic.LoadInt64(&storage.iamAuthenticatedCalls) == 0 || endpoint.SessionExpiries() == nil {
		t.Fatal("restic never used one-run IAM credentials")
	}
	objects := storage.inventory()
	if len(objects) < 5 {
		t.Fatalf("incomplete repository inventory: %#v", objects)
	}
	for _, prefix := range []string{"generation-offsite-real/config", "generation-offsite-real/keys/", "generation-offsite-real/data/", "generation-offsite-real/index/", "generation-offsite-real/snapshots/"} {
		if !containsObjectPrefix(objects, prefix) {
			t.Fatalf("missing protected prefix %q in %#v", prefix, objects)
		}
	}
}

type hermeticS3 struct {
	t                     *testing.T
	server                *httptest.Server
	mu                    sync.Mutex
	objects               map[string][]byte
	iamAuthenticatedCalls int64
}

func newHermeticS3(t *testing.T) *hermeticS3 {
	fixture := &hermeticS3{t: t, objects: map[string][]byte{}}
	fixture.server = httptest.NewServer(http.HandlerFunc(fixture.serveHTTP))
	return fixture
}

func (fixture *hermeticS3) serveHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Query().Has("location") {
		writer.Header().Set("Content-Type", "application/xml")
		_, _ = io.WriteString(writer, `<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></LocationConstraint>`)
		return
	}
	if request.URL.Path == "/bucket" || request.URL.Path == "/bucket/" {
		writer.WriteHeader(http.StatusOK)
		return
	}
	if !strings.HasPrefix(request.URL.Path, "/bucket/") {
		http.NotFound(writer, request)
		return
	}
	if request.Header.Get("Authorization") == "" || request.Header.Get("X-Amz-Security-Token") == "" {
		http.Error(writer, "forbidden", http.StatusForbidden)
		return
	}
	atomic.AddInt64(&fixture.iamAuthenticatedCalls, 1)
	if request.URL.Query().Get("list-type") == "2" {
		fixture.list(writer, request.URL.Query().Get("prefix"))
		return
	}
	key := strings.TrimPrefix(request.URL.Path, "/bucket/")
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	switch request.Method {
	case http.MethodPut:
		body, err := io.ReadAll(io.LimitReader(request.Body, 64<<20))
		if err != nil {
			http.Error(writer, "read", http.StatusInternalServerError)
			return
		}
		fixture.objects[key] = append([]byte(nil), body...)
		sum := md5.Sum(body)
		writer.Header().Set("ETag", `"`+hex.EncodeToString(sum[:])+`"`)
		writer.WriteHeader(http.StatusOK)
	case http.MethodHead:
		body, ok := fixture.objects[key]
		if !ok {
			writeS3Missing(writer, key)
			return
		}
		writer.Header().Set("Content-Length", fmt.Sprint(len(body)))
		writer.WriteHeader(http.StatusOK)
	case http.MethodGet:
		body, ok := fixture.objects[key]
		if !ok {
			writeS3Missing(writer, key)
			return
		}
		http.ServeContent(writer, request, key, time.Unix(1, 0), bytes.NewReader(body))
	case http.MethodDelete:
		delete(fixture.objects, key)
		writer.WriteHeader(http.StatusNoContent)
	default:
		http.Error(writer, "method", http.StatusMethodNotAllowed)
	}
}

func writeS3Missing(writer http.ResponseWriter, key string) {
	writer.Header().Set("Content-Type", "application/xml")
	writer.WriteHeader(http.StatusNotFound)
	_, _ = fmt.Fprintf(writer, `<Error><Code>NoSuchKey</Code><Message>missing</Message><BucketName>bucket</BucketName><Key>%s</Key><RequestId>fixture</RequestId><HostId>fixture</HostId></Error>`, key)
}

func (fixture *hermeticS3) list(writer http.ResponseWriter, prefix string) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	type content struct {
		Key          string `xml:"Key"`
		LastModified string `xml:"LastModified"`
		ETag         string `xml:"ETag"`
		Size         int    `xml:"Size"`
		StorageClass string `xml:"StorageClass"`
	}
	result := struct {
		XMLName                         xml.Name `xml:"ListBucketResult"`
		Xmlns                           string   `xml:"xmlns,attr"`
		Name, Prefix, KeyCount, MaxKeys string
		IsTruncated                     bool
		Contents                        []content `xml:"Contents"`
	}{Xmlns: "http://s3.amazonaws.com/doc/2006-03-01/", Name: "bucket", Prefix: prefix, MaxKeys: "1000"}
	for key, body := range fixture.objects {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		sum := md5.Sum(body)
		result.Contents = append(result.Contents, content{Key: key, LastModified: time.Unix(1, 0).UTC().Format(time.RFC3339), ETag: `"` + hex.EncodeToString(sum[:]) + `"`, Size: len(body), StorageClass: "STANDARD"})
	}
	sort.Slice(result.Contents, func(i, j int) bool { return result.Contents[i].Key < result.Contents[j].Key })
	result.KeyCount = fmt.Sprint(len(result.Contents))
	writer.Header().Set("Content-Type", "application/xml")
	_ = xml.NewEncoder(writer).Encode(result)
}

func (fixture *hermeticS3) inventory() []string {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	result := make([]string, 0, len(fixture.objects))
	for key := range fixture.objects {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}

func containsObjectPrefix(objects []string, prefix string) bool {
	for _, object := range objects {
		if object == prefix || strings.HasPrefix(object, prefix) {
			return true
		}
	}
	return false
}

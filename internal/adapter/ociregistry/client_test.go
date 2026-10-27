package ociregistry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
)

func sum(b []byte) string { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }
func image() PublishRequest {
	config, layer := []byte(`{"architecture":"amd64","os":"linux"}`), []byte("actual layer tar bytes")
	desc := func(mt string, b []byte) map[string]any {
		return map[string]any{"mediaType": mt, "digest": sum(b), "size": len(b)}
	}
	manifest, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": desc("application/vnd.oci.image.config.v1+json", config), "layers": []any{desc("application/vnd.oci.image.layer.v1.tar", layer)}})
	q := PublishRequest{Repository: "team/app", Digest: sum(manifest), Manifest: manifest, Check: func() error { return nil }}
	for _, data := range [][]byte{config, layer} {
		q.Blobs = append(q.Blobs, Blob{Digest: sum(data), Size: int64(len(data)), Open: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil }})
	}
	return q
}

type registry struct {
	mu              sync.Mutex
	blobs           map[string][]byte
	manifest        []byte
	calls           []string
	location        string
	wrongDigest     bool
	headWrong       bool
	deny            bool
	oversized       bool
	wrongBytes      bool
	failMethod      string
	failStatus      int
	duplicateHeader bool
	lost            bool
}

func fixture(t *testing.T) (*Client, *registry, *credentialref.Value) {
	t.Helper()
	f := &registry{blobs: map[string][]byte{}}
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls = append(f.calls, r.Method+" "+r.URL.RequestURI())
		if r.Header.Get("Authorization") != "Bearer fixture-secret" {
			t.Error("missing scoped credential")
			w.WriteHeader(401)
			return
		}
		if f.deny {
			w.Header().Set("WWW-Authenticate", `Bearer realm="https://foreign.invalid/token"`)
			w.WriteHeader(401)
			return
		}
		prefix := "/v2/team/app/"
		if !strings.HasPrefix(r.URL.Path, prefix) {
			t.Error("scope widened")
			w.WriteHeader(400)
			return
		}
		if f.failMethod == r.Method {
			w.Header().Set("Location", "https://foreign.invalid/redirect")
			w.WriteHeader(f.failStatus)
			return
		}
		tail := strings.TrimPrefix(r.URL.Path, prefix)
		switch {
		case r.Method == "HEAD" && strings.HasPrefix(tail, "blobs/sha256:"):
			b, ok := f.blobs[strings.TrimPrefix(tail, "blobs/")]
			if !ok {
				w.WriteHeader(404)
				return
			}
			w.Header().Set("Docker-Content-Digest", sum(b))
			if f.headWrong {
				w.Header().Set("Docker-Content-Digest", sum([]byte("other")))
			}
			w.Header().Set("Content-Length", strconv.Itoa(len(b)))
			w.WriteHeader(200)
		case r.Method == "POST" && tail == "blobs/uploads/":
			loc := prefix + "blobs/uploads/upload-1?_state=opaque_state=="
			if f.location != "" {
				loc = f.location
			}
			w.Header().Set("Location", loc)
			if f.duplicateHeader {
				w.Header().Add("Location", loc)
			}
			w.WriteHeader(202)
		case r.Method == "PUT" && tail == "blobs/uploads/upload-1":
			if r.URL.Query().Get("_state") != "opaque_state==" {
				t.Error("state not preserved")
			}
			b, _ := io.ReadAll(r.Body)
			if sum(b) != r.URL.Query().Get("digest") {
				w.WriteHeader(400)
				return
			}
			f.blobs[sum(b)] = b
			if f.lost {
				h := w.(http.Hijacker)
				conn, _, _ := h.Hijack()
				conn.Close()
				return
			}
			w.Header().Set("Docker-Content-Digest", sum(b))
			w.WriteHeader(201)
		case r.Method == "PUT" && strings.HasPrefix(tail, "manifests/sha256:"):
			b, _ := io.ReadAll(r.Body)
			if sum(b) != strings.TrimPrefix(tail, "manifests/") {
				w.WriteHeader(400)
				return
			}
			f.manifest = b
			w.Header().Set("Docker-Content-Digest", sum(b))
			w.WriteHeader(201)
		case r.Method == "GET" && strings.HasPrefix(tail, "manifests/sha256:"):
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			d := sum(f.manifest)
			if f.wrongDigest {
				d = sum([]byte("wrong"))
			}
			w.Header().Set("Docker-Content-Digest", d)
			if f.oversized {
				w.Write(bytes.Repeat([]byte("a"), maxManifest+1))
				return
			}
			if f.wrongBytes {
				w.Write([]byte("other"))
				return
			}
			w.Write(f.manifest)
		default:
			t.Error("unexpected route", r.Method, r.URL)
			w.WriteHeader(400)
		}
	}))
	t.Cleanup(s.Close)
	c, err := NewClient(s.URL, s.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	v, _ := credentialref.NewValue([]byte("fixture-secret"))
	t.Cleanup(v.Close)
	return c, f, v
}
func TestPublishExactBytes(t *testing.T) {
	c, f, v := fixture(t)
	q := image()
	out, err := c.Publish(context.Background(), q, v)
	if err != nil || !out.Verified || out.Digest != q.Digest {
		t.Fatal(out, err)
	}
	if !bytes.Equal(f.manifest, q.Manifest) || len(f.blobs) != 2 {
		t.Fatal("remote bytes differ")
	}
}
func TestScopeDenial(t *testing.T) {
	c, f, v := fixture(t)
	q := image()
	q.Repository = "../another"
	if _, err := c.Publish(context.Background(), q, v); err == nil {
		t.Fatal("unsafe repo accepted")
	}
	if len(f.calls) != 0 {
		t.Fatal("invalid input contacted registry")
	}
}

func TestExistingBlobs(t *testing.T) {
	c, f, v := fixture(t)
	q := image()
	for _, b := range q.Blobs {
		r, _ := b.Open()
		f.blobs[b.Digest], _ = io.ReadAll(r)
		r.Close()
	}
	out, err := c.Publish(context.Background(), q, v)
	if err != nil || !out.Verified {
		t.Fatal(out, err)
	}
	for _, call := range f.calls {
		if strings.HasPrefix(call, "POST ") || strings.Contains(call, "uploads") {
			t.Fatal("existing blob reuploaded")
		}
	}
}
func TestLocationDenials(t *testing.T) {
	for _, loc := range []string{"https://foreign.invalid/v2/team/app/blobs/uploads/id", "/v2/other/app/blobs/uploads/id", "/v2/team/app/blobs/uploads/../id", "/v2/team/app/blobs/uploads/x/../id", "/v2/team/app/blobs/uploads/id?digest=sha256:other", "/v2/team/app/blobs/uploads/id?_state=a&_state=b", "/v2/team/app/blobs/uploads/id?_state=bad%0A", "/v2/team/app/blobs/uploads/id?mount=another", "/v2/team/app/blobs/uploads/id#fragment", "/v2/team/app/blobs/uploads/%69d"} {
		t.Run(loc, func(t *testing.T) {
			c, f, v := fixture(t)
			f.location = loc
			out, err := c.Publish(context.Background(), image(), v)
			if err == nil || out.Stage != "blob_upload_start_attempted" || out.Verified {
				t.Fatal(out, err)
			}
			if len(f.calls) != 2 {
				t.Fatal("followed unsafe location", f.calls)
			}
		})
	}
}
func TestSourceDriftDeniesManifest(t *testing.T) {
	for _, kind := range []string{"hash", "short", "long", "reader error", "close error"} {
		t.Run(kind, func(t *testing.T) {
			c, f, v := fixture(t)
			q := image()
			b := q.Blobs[0]
			opens := 0
			closed := 0
			q.Blobs[0].Open = func() (io.ReadCloser, error) {
				opens++
				r, _ := b.Open()
				data, _ := io.ReadAll(r)
				r.Close()
				var failure error
				if opens > 1 {
					switch kind {
					case "hash":
						data[0] ^= 1
					case "short":
						data = data[:len(data)-1]
					case "long":
						data = append(data, 'x')
					case "reader error":
						failure = errors.New("fixture-secret")
					case "close error":
					}
				}
				return &testReader{Reader: bytes.NewReader(data), readErr: failure, closeErr: kind == "close error" && opens > 1, closed: &closed}, nil
			}
			out, err := c.Publish(context.Background(), q, v)
			if err == nil || out.Verified || len(f.manifest) != 0 {
				t.Fatal(out, err)
			}
			if strings.Contains(err.Error(), "fixture-secret") {
				t.Fatal("leaked source error")
			}
			if closed != 2 {
				t.Fatal("unclosed source", closed)
			}
		})
	}
}

type testReader struct {
	*bytes.Reader
	readErr  error
	closeErr bool
	closed   *int
}

func (r *testReader) Read(p []byte) (int, error) {
	if r.readErr != nil {
		return 0, r.readErr
	}
	return r.Reader.Read(p)
}
func (r *testReader) Close() error {
	*r.closed++
	if r.closeErr {
		return errors.New("fixture-secret")
	}
	return nil
}

func TestMalformedInputsBeforeNetwork(t *testing.T) {
	cases := map[string]func(*PublishRequest){
		"wrong manifest digest": func(q *PublishRequest) { q.Digest = sum([]byte("other")) },
		"missing blob":          func(q *PublishRequest) { q.Blobs = q.Blobs[:1] },
		"duplicate blob":        func(q *PublishRequest) { q.Blobs[1] = q.Blobs[0] },
		"bad blob size":         func(q *PublishRequest) { q.Blobs[0].Size++ },
		"too large blob":        func(q *PublishRequest) { q.Blobs[0].Size = maxBlob + 1 },
		"missing reader":        func(q *PublishRequest) { q.Blobs[0].Open = nil },
		"source wrong bytes": func(q *PublishRequest) {
			q.Blobs[0].Open = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("wrong")), nil }
		},
		"source error": func(q *PublishRequest) {
			q.Blobs[0].Open = func() (io.ReadCloser, error) { return nil, errors.New("fixture-secret") }
		},
		"tag digest":      func(q *PublishRequest) { q.Digest = "latest" },
		"case repository": func(q *PublishRequest) { q.Repository = "Team/app" },
		"check missing":   func(q *PublishRequest) { q.Check = nil },
		"too many blobs":  func(q *PublishRequest) { q.Blobs = make([]Blob, 129) },
		"oversized manifest": func(q *PublishRequest) {
			q.Manifest = bytes.Repeat([]byte("a"), maxManifest+1)
			q.Digest = sum(q.Manifest)
		},
	}
	for _, raw := range []string{`{"schemaVersion":2,"schemaVersion":2}`, `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json"}`, `{"schemaVersion":2,"unknown":1}`, strings.Repeat("[", 10) + strings.Repeat("]", 10)} {
		raw := raw
		cases[raw] = func(q *PublishRequest) { q.Manifest = []byte(raw); q.Digest = sum(q.Manifest) }
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c, f, v := fixture(t)
			q := image()
			mutate(&q)
			out, err := c.Publish(context.Background(), q, v)
			if err == nil || out.Verified || len(f.calls) > 0 {
				t.Fatal(out, err, f.calls)
			}
			if strings.Contains(err.Error(), "fixture-secret") {
				t.Fatal("secret error")
			}
		})
	}
}

func TestRemoteFailures(t *testing.T) {
	for _, kind := range []string{"remote digest", "remote bytes", "oversized", "HEAD digest", "denied", "lost response"} {
		t.Run(kind, func(t *testing.T) {
			c, f, v := fixture(t)
			q := image()
			switch kind {
			case "remote digest":
				f.wrongDigest = true
			case "remote bytes":
				f.wrongBytes = true
			case "oversized":
				f.oversized = true
			case "HEAD digest":
				f.headWrong = true
				r, _ := q.Blobs[0].Open()
				f.blobs[q.Blobs[0].Digest], _ = io.ReadAll(r)
				r.Close()
			case "denied":
				f.deny = true
			case "lost response":
				f.lost = true
			}
			out, err := c.Publish(context.Background(), q, v)
			if err == nil || out.Verified {
				t.Fatal(out, err)
			}
			if strings.Contains(err.Error(), "fixture-secret") {
				t.Fatal("secret exposed")
			}
			if kind == "lost response" {
				if out.Stage != "blob_upload_attempted" || len(f.calls) != 3 || len(f.blobs) != 1 || len(f.manifest) > 0 {
					t.Fatal("lost effect retried or unrecorded", out, f.calls)
				}
			}
		})
	}
}
func TestChecksAndCancellation(t *testing.T) {
	c, f, v := fixture(t)
	q := image()
	checks := 0
	q.Check = func() error {
		checks++
		if checks == 5 {
			return errors.New("fixture-secret")
		}
		return nil
	}
	out, err := c.Publish(context.Background(), q, v)
	if err == nil || out.Verified || strings.Contains(err.Error(), "fixture-secret") {
		t.Fatal(out, err)
	}
	if len(f.calls) != 2 {
		t.Fatal("check missed request", f.calls)
	}
	c, f, v = fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out, err = c.Publish(ctx, image(), v)
	if err == nil || len(f.calls) != 0 {
		t.Fatal(out, err)
	}
	c, f, v = fixture(t)
	q = image()
	q.Check = func() error { cancel(); return nil }
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	if _, err := c.Publish(ctx, q, v); err == nil || len(f.calls) != 0 {
		t.Fatal("check cancellation not enforced")
	}
}
func TestOriginAndCredentialDenials(t *testing.T) {
	for _, origin := range []string{"http://registry.invalid", "https://user:password@registry.invalid", "https://registry.invalid/path", "https://registry.invalid?query", "https://registry.invalid/#fragment", "https://registry.invalid?"} {
		if _, err := NewClient(origin, nil); err == nil {
			t.Fatal("unsafe origin", origin)
		}
	}
	c, f, v := fixture(t)
	v.Close()
	if _, err := c.Publish(context.Background(), image(), v); err == nil || len(f.calls) != 0 {
		t.Fatal("closed credential accepted")
	}
}
func TestCancelDuringRequest(t *testing.T) {
	entered := make(chan struct{})
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-r.Context().Done() }))
	defer s.Close()
	c, _ := NewClient(s.URL, s.Client().Transport)
	v, _ := credentialref.NewValue([]byte("fixture-secret"))
	defer v.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := c.Publish(ctx, image(), v); done <- err }()
	<-entered
	cancel()
	if err := <-done; err == nil {
		t.Fatal("cancellation ignored")
	}
}

func TestManifestDescriptorDenials(t *testing.T) {
	for _, kind := range []string{"duplicate descriptor", "missing size", "negative size", "wrong media", "missing config", "missing layer", "extra descriptor"} {
		t.Run(kind, func(t *testing.T) {
			c, f, v := fixture(t)
			q := image()
			var m map[string]any
			json.Unmarshal(q.Manifest, &m)
			config := m["config"].(map[string]any)
			layers := m["layers"].([]any)
			switch kind {
			case "duplicate descriptor":
				m["layers"] = []any{config}
			case "missing size":
				delete(config, "size")
			case "negative size":
				config["size"] = -1
			case "wrong media":
				layers[0].(map[string]any)["mediaType"] = "application/unknown"
			case "missing config":
				delete(m, "config")
			case "missing layer":
				m["layers"] = []any{}
			case "extra descriptor":
				m["layers"] = append(layers, layers[0])
			}
			q.Manifest, _ = json.Marshal(m)
			q.Digest = sum(q.Manifest)
			if _, err := c.Publish(context.Background(), q, v); err == nil || len(f.calls) != 0 {
				t.Fatal("descriptor accepted", kind, err)
			}
		})
	}
}
func TestStatusAndRedirectDenials(t *testing.T) {
	for _, method := range []string{"HEAD", "POST", "PUT"} {
		for _, status := range []int{http.StatusTemporaryRedirect, http.StatusForbidden, http.StatusInternalServerError} {
			t.Run(method+strconv.Itoa(status), func(t *testing.T) {
				c, f, v := fixture(t)
				f.failMethod = method
				f.failStatus = status
				out, err := c.Publish(context.Background(), image(), v)
				if err == nil || out.Verified {
					t.Fatal(out, err)
				}
				count := 0
				for _, call := range f.calls {
					if strings.HasPrefix(call, method+" ") {
						count++
					}
				}
				if count != 1 {
					t.Fatal("retried failed request", f.calls)
				}
			})
		}
	}
	c, f, v := fixture(t)
	f.duplicateHeader = true
	out, err := c.Publish(context.Background(), image(), v)
	if err == nil || out.Stage != "blob_upload_start_attempted" || len(f.calls) != 2 {
		t.Fatal("ambiguous upload location accepted", out, err)
	}
}

func TestAnnotatedImage(t *testing.T) {
	c, f, v := fixture(t)
	q := image()
	var m map[string]any
	json.Unmarshal(q.Manifest, &m)
	m["annotations"] = map[string]string{"org.opencontainers.image.title": "fixture image", "org.opencontainers.image.source": "https://source.invalid/team/app"}
	m["config"].(map[string]any)["annotations"] = map[string]string{"org.opencontainers.image.description": "AMD64 Linux configuration"}
	m["layers"].([]any)[0].(map[string]any)["annotations"] = map[string]string{"org.opencontainers.image.title": "layer.tar"}
	q.Manifest, _ = json.Marshal(m)
	q.Digest = sum(q.Manifest)
	out, err := c.Publish(context.Background(), q, v)
	if err != nil || !out.Verified || !bytes.Equal(f.manifest, q.Manifest) {
		t.Fatal(out, err)
	}
}
func TestAnnotationLimits(t *testing.T) {
	for _, kind := range []string{"count", "key", "value", "total", "type"} {
		t.Run(kind, func(t *testing.T) {
			c, f, v := fixture(t)
			q := image()
			var m map[string]any
			json.Unmarshal(q.Manifest, &m)
			a := map[string]any{}
			switch kind {
			case "count":
				for i := range 33 {
					a[strconv.Itoa(i)] = "value"
				}
			case "key":
				a[strings.Repeat("k", 129)] = "value"
			case "value":
				a["key"] = strings.Repeat("v", 1025)
			case "total":
				for i := range 9 {
					a[strconv.Itoa(i)] = strings.Repeat("v", 1024)
				}
			case "type":
				a["key"] = 123
			}
			m["annotations"] = a
			q.Manifest, _ = json.Marshal(m)
			q.Digest = sum(q.Manifest)
			if _, err := c.Publish(context.Background(), q, v); err == nil || len(f.calls) != 0 {
				t.Fatal("unbounded annotations accepted", err)
			}
		})
	}
}

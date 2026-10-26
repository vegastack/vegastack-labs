package harbor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/failure"
)

var testDigest = "sha256:" + strings.Repeat("a", 64)

func testSecret(t *testing.T) *credentialref.Value {
	t.Helper()
	v, e := credentialref.NewValue([]byte("secret-do-not-return"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(v.Close)
	return v
}
func target() ArtifactTarget {
	return ArtifactTarget{Project: "project", Repository: "nested/image", Digest: testDigest, ProjectID: 7, RepositoryID: 9}
}
func artifact(extra string) string {
	return fmt.Sprintf(`{"digest":%q,"project_id":7,"repository_id":9,"repository_name":"project/nested/image","manifest_media_type":"application/vnd.oci.image.manifest.v1+json"%s}`, testDigest, extra)
}
func peer(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	s := httptest.NewTLSServer(handler)
	t.Cleanup(s.Close)
	c, e := NewClient(s.URL, s.Client().Transport)
	if e != nil {
		t.Fatal(e)
	}
	return c, s
}

func TestMismatchedIdentityIsRejected(t *testing.T) {
	c, _ := peer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, strings.Replace(artifact(`,"private":"secret-do-not-return"`), testDigest, "sha256:"+strings.Repeat("b", 64), 1))
	})
	out, e := c.InspectArtifact(context.Background(), target(), "robot$ci", testSecret(t))
	if e == nil || out.Digest != "" || strings.Contains(e.Error(), "secret-do-not-return") {
		t.Fatalf("unsafe mismatch result: %+v %v", out, e)
	}
}

func TestExactTLSArtifactRead(t *testing.T) {
	var calls atomic.Int32
	c, _ := peer(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		want := "/api/v2.0/projects/project/repositories/nested%252Fimage/artifacts/" + testDigest + "?with_scan_overview=true"
		if r.Method != "GET" || r.RequestURI != want {
			t.Errorf("unexpected request %s %s", r.Method, r.RequestURI)
		}
		user, password, ok := r.BasicAuth()
		if !ok || user != "robot$ci" || password != "secret-do-not-return" {
			t.Error("wrong scoped authentication")
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, artifact(`,"scan_overview":{"application/vnd.security.vulnerability.report; version=1.1":{"scan_status":"Success","complete_percent":100,"summary":{"total":0}}},"unknown":{"private":"do-not-export"}`))
	})
	secret := testSecret(t)
	out, e := c.InspectArtifact(context.Background(), target(), "robot$ci", secret)
	if e != nil {
		t.Fatal(e)
	}
	if out.Digest != testDigest || out.Kind != "image" || out.ScanState != "passed" || out.SignatureState != "unverified" || out.ProvenanceState != "unverified" || out.ObservedAt.IsZero() || calls.Load() != 1 {
		t.Fatalf("incorrect snapshot %+v", out)
	}
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), "do-not-export") {
		t.Fatal("unknown field escaped")
	}
	if string(secret.Bytes()) != "secret-do-not-return" {
		t.Fatal("caller credential closed")
	}
}

func TestScanStatesAndIndex(t *testing.T) {
	cases := []struct{ name, extra, want string }{
		{"absent", "", "not-scanned"},
		{"empty", `,"scan_overview":{}`, "not-scanned"},
		{"findings", `,"scan_overview":{"application/vnd.security.vulnerability.report; version=1.1":{"scan_status":"Success","complete_percent":100,"summary":{"total":4}}}`, "findings"},
		{"running", `,"scan_overview":{"application/vnd.security.vulnerability.report; version=1.1":{"scan_status":"Running","complete_percent":42}}`, "running"},
		{"pending", `,"scan_overview":{"application/vnd.security.vulnerability.report; version=1.1":{"scan_status":"Pending"}}`, "pending"},
		{"error", `,"scan_overview":{"application/vnd.security.vulnerability.report; version=1.1":{"scan_status":"Error"}}`, "error"},
		{"unknown", `,"scan_overview":{"private-untrusted":{"scan_status":"Success","summary":{"total":0}}}`, "unavailable"},
		{"incomplete-success", `,"scan_overview":{"application/vnd.security.vulnerability.report; version=1.1":{"scan_status":"Success","complete_percent":99,"summary":{"total":0}}}`, "unavailable"},
		{"missing-total", `,"scan_overview":{"application/vnd.security.vulnerability.report; version=1.1":{"scan_status":"Success","complete_percent":100,"summary":{}}}`, "unavailable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := peer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, artifact(tc.extra))
			})
			o, e := c.InspectArtifact(context.Background(), target(), "robot", testSecret(t))
			if e != nil || o.ScanState != tc.want {
				t.Fatalf("got %+v %v", o, e)
			}
		})
	}
	t.Run("index", func(t *testing.T) {
		c, _ := peer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, strings.Replace(artifact(""), "application/vnd.oci.image.manifest.v1+json", "application/vnd.oci.image.index.v1+json", 1))
		})
		o, e := c.InspectArtifact(context.Background(), target(), "robot", testSecret(t))
		if e != nil || o.Kind != "index" || o.PlatformVerified {
			t.Fatalf("index mistaken for running platform %+v %v", o, e)
		}
	})
}

func TestMalformedOrWrongScope(t *testing.T) {
	cases := map[string]string{
		"project":          strings.Replace(artifact(""), `"project_id":7`, `"project_id":8`, 1),
		"repository-id":    strings.Replace(artifact(""), `"repository_id":9`, `"repository_id":8`, 1),
		"repository-name":  strings.Replace(artifact(""), `project/nested/image`, `other/nested/image`, 1),
		"duplicate":        artifact(`,"digest":"private-secret"`),
		"case-alias":       artifact(`,"Digest":"private-secret"`),
		"nested-duplicate": artifact(`,"unknown":{"a":1,"a":2}`),
		"trailing":         artifact("") + ` {}`,
		"array":            `[]`,
		"null":             `null`,
		"malformed":        `{"private":"private-secret"`,
		"oversized":        artifact(`,"unknown":"` + strings.Repeat("x", maxBody) + `"`),
		"deep":             artifact(`,"unknown":` + strings.Repeat("[", 40) + `0` + strings.Repeat("]", 40)),
	}
	for n, body := range cases {
		t.Run(n, func(t *testing.T) {
			c, _ := peer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, body)
			})
			o, e := c.InspectArtifact(context.Background(), target(), "robot", testSecret(t))
			if e == nil || o.Digest != "" || strings.Contains(e.Error(), "private-secret") {
				t.Fatalf("unsafe parse result %+v %v", o, e)
			}
		})
	}
}

func TestStatusAndRedirectNeverRetries(t *testing.T) {
	for _, status := range []int{301, 302, 307, 308, 401, 403, 404, 429, 500, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var count atomic.Int32
			var destination atomic.Int32
			dest := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { destination.Add(1) }))
			defer dest.Close()
			c, _ := peer(t, func(w http.ResponseWriter, r *http.Request) {
				count.Add(1)
				w.Header().Set("Location", dest.URL)
				w.WriteHeader(status)
				fmt.Fprint(w, `secret-do-not-return`)
			})
			o, e := c.InspectArtifact(context.Background(), target(), "robot", testSecret(t))
			wantCode := "DEPENDENCY_UNAVAILABLE"
			switch status {
			case 401:
				wantCode = "AUTHENTICATION_REQUIRED"
			case 403:
				wantCode = "AUTHORIZATION_DENIED"
			case 404:
				wantCode = "RESOURCE_NOT_FOUND"
			case 429:
				wantCode = "RATE_LIMITED"
			}
			stable, ok := failure.As(e)
			if !ok || stable.Code != wantCode {
				t.Fatalf("wrong stable code: %v want %s", e, wantCode)
			}
			if e == nil || o.Digest != "" || count.Load() != 1 || destination.Load() != 0 || strings.Contains(e.Error(), "secret-do-not-return") {
				t.Fatalf("unsafe status handling %+v %v calls=%d dest=%d", o, e, count.Load(), destination.Load())
			}
		})
	}
}

func TestInputsAndTransportBounds(t *testing.T) {
	for _, u := range []string{"http://registry.example", "https://u:p@registry.example", "https://registry.example/api", "https://registry.example?x=y", "https://registry.example#x", "https://registry.example/../", "https://registry.example\\bad", "https://registry.example:bad", "https://registry.example:0"} {
		if _, e := NewClient(u, nil); e == nil {
			t.Errorf("accepted invalid origin %s", u)
		}
	}
	var calls atomic.Int32
	c, s := peer(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, artifact(""))
	})
	bad := []ArtifactTarget{{Project: "project", Repository: "../other", Digest: testDigest}, {Project: "project", Repository: "a%2Fb", Digest: testDigest}, {Project: "project", Repository: "image", Digest: "latest"}, {Project: "other/x", Repository: "image", Digest: testDigest}}
	for _, q := range bad {
		if _, e := c.InspectArtifact(context.Background(), q, "robot", testSecret(t)); e == nil {
			t.Error("invalid target accepted")
		}
	}
	for _, user := range []string{"", "robot:other", "robot\n", "robot\x00"} {
		if _, e := c.InspectArtifact(context.Background(), target(), user, testSecret(t)); e == nil {
			t.Error("bad username accepted")
		}
	}
	closed := testSecret(t)
	closed.Close()
	if _, e := c.InspectArtifact(context.Background(), target(), "robot", closed); e == nil {
		t.Error("closed secret accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := c.InspectArtifact(ctx, target(), "robot", testSecret(t)); e == nil {
		t.Error("cancel ignored")
	}
	if calls.Load() != 0 {
		t.Fatal("invalid input/cancel reached peer")
	}
	untrusted, e := NewClient(s.URL, nil)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := untrusted.InspectArtifact(context.Background(), target(), "robot", testSecret(t)); e == nil {
		t.Error("untrusted TLS accepted")
	}
	t.Run("deadline", func(t *testing.T) {
		cc, _ := peer(t, func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		start := time.Now()
		if _, e := cc.InspectArtifact(ctx, target(), "robot", testSecret(t)); e == nil || time.Since(start) > time.Second {
			t.Fatal("request did not respect deadline")
		}
	})
}

func TestDefaultTransportHasNoProxyOrConnectionReuse(t *testing.T) {
	c, e := NewClient("https://registry.example", nil)
	if e != nil {
		t.Fatal(e)
	}
	tr, ok := c.http.Transport.(*http.Transport)
	if !ok || tr.Proxy != nil || !tr.DisableKeepAlives || !tr.DisableCompression || c.http.Timeout != requestTimeout {
		t.Fatal("default transport inherited ambient behavior")
	}
}

func TestInvalidSecretDoesNotReachPeer(t *testing.T) {
	c, _ := peer(t, func(w http.ResponseWriter, r *http.Request) { t.Error("invalid secret reached peer") })
	for _, raw := range []string{"secret\r", "secret\n", "secret\x00"} {
		v, e := credentialref.NewValue([]byte(raw))
		if e != nil {
			t.Fatal(e)
		}
		if _, e = c.InspectArtifact(context.Background(), target(), "robot", v); e == nil {
			t.Error("invalid credential accepted")
		}
		v.Close()
	}
}

func TestTruncatedBodyAndWrongContentType(t *testing.T) {
	for _, mode := range []string{"truncated", "wrong-content-type"} {
		t.Run(mode, func(t *testing.T) {
			c, _ := peer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if mode == "truncated" {
					w.Header().Set("Content-Length", fmt.Sprint(len(artifact(""))+50))
				} else {
					w.Header().Set("Content-Type", "text/html")
				}
				fmt.Fprint(w, artifact(""))
			})
			o, e := c.InspectArtifact(context.Background(), target(), "robot", testSecret(t))
			stable, ok := failure.As(e)
			if !ok || stable.Code != "INTEGRITY_FAILURE" || o.Digest != "" {
				t.Fatalf("unsafe response %+v %v", o, e)
			}
		})
	}
}

func TestUnknownMediaDoesNotEscapeOrVerifyPlatform(t *testing.T) {
	c, _ := peer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, strings.Replace(artifact(""), "application/vnd.oci.image.manifest.v1+json", "private-provider-value", 1))
	})
	o, e := c.InspectArtifact(context.Background(), target(), "robot", testSecret(t))
	if e != nil || o.Kind != "unknown" || o.ManifestMediaType != "" || o.PlatformVerified {
		t.Fatalf("unknown media incorrectly verified %+v %v", o, e)
	}
}

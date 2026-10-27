// Package ociregistry implements a fixed OCI Distribution 1.1.1 image upload.
// Receipts establish registry bytes only, never signing or deployment authority.
package ociregistry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"hash"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/strictjson"
)

const (
	maxManifest  = 1 << 20
	maxBlob      = 1 << 30
	maxTotal     = 4 << 30
	manifestType = "application/vnd.oci.image.manifest.v1+json"
	configType   = "application/vnd.oci.image.config.v1+json"
	layerType    = "application/vnd.oci.image.layer.v1.tar"
)

var (
	ErrInput       = failure.New(generated.ErrorCodeInputInvalid, "oci-registry", false)
	ErrIdentity    = failure.New(generated.ErrorCodeIntegrityFailure, "oci-registry", false)
	ErrDenied      = failure.New(generated.ErrorCodeAuthorizationDenied, "oci-registry", false)
	ErrUnavailable = failure.New(generated.ErrorCodeDependencyUnavailable, "oci-registry", false)
	ErrInterrupted = failure.New(generated.ErrorCodeInterrupted, "oci-registry", false)
	repositoryName = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$`)
	digestName     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	uploadID       = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	uploadState    = regexp.MustCompile(`^[A-Za-z0-9_=-]+$`)
)

type Blob struct {
	Digest string
	Size   int64
	Open   func() (io.ReadCloser, error)
}
type PublishRequest struct {
	Repository, Digest string
	Manifest           []byte
	Blobs              []Blob
	Check              func() error
}

// PublishReceipt.Stage must be retained on error: an attempted mutation can have
// succeeded remotely even when its response is lost. There is no automatic retry.
type PublishReceipt struct {
	Repository, Digest, Stage string
	Verified                  bool
}
type Client struct {
	origin *url.URL
	http   *http.Client
}

// NewClient accepts a configured HTTPS origin only. A supplied transport is a
// trusted composition boundary (including its TLS policy), never provider data.
func NewClient(origin string, transport http.RoundTripper) (*Client, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, ErrInput
	}
	u.Path = ""
	if t, ok := transport.(*http.Transport); ok {
		clone := t.Clone()
		clone.Proxy = nil
		clone.DisableKeepAlives = true
		transport = clone
	}
	if transport == nil {
		transport = &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, DisableKeepAlives: true, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second, IdleConnTimeout: 30 * time.Second}
	}
	return &Client{origin: u, http: &http.Client{Transport: transport, Timeout: 2 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

type descriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        *int64            `json:"size"`
	Annotations map[string]string `json:"annotations,omitempty"`
}
type manifest struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType"`
	Config        descriptor        `json:"config"`
	Layers        []descriptor      `json:"layers"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

// Annotations remain opaque bounded metadata, included in the exact byte hash
// but never interpreted as URLs, identity, authority or receipt data.
func validAnnotations(a map[string]string) bool {
	if len(a) > 32 {
		return false
	}
	total := 0
	for k, v := range a {
		if len(k) == 0 || len(k) > 128 || len(v) > 1024 || !utf8.ValidString(k) || !utf8.ValidString(v) {
			return false
		}
		total += len(k) + len(v)
	}
	return total <= 8192
}

func digestOf(b []byte) string { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }
func (c *Client) validate(ctx context.Context, q PublishRequest, v *credentialref.Value) error {
	if c == nil || c.http == nil || c.origin == nil || q.Check == nil || len(q.Repository) > 255 || !repositoryName.MatchString(q.Repository) || !digestName.MatchString(q.Digest) || len(q.Manifest) == 0 || len(q.Manifest) > maxManifest || digestOf(q.Manifest) != q.Digest || len(q.Blobs) < 1 || len(q.Blobs) > 128 || !credentialOK(v) {
		return ErrInput
	}
	if strings.Contains(q.Repository, string(v.Bytes())) {
		return ErrInput
	}
	if strictjson.Scan(ctx, q.Manifest, strictjson.Limits{MaxDepth: 8}) != nil {
		return ErrInput
	}
	var m manifest
	d := json.NewDecoder(bytes.NewReader(q.Manifest))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil || m.SchemaVersion != 2 || m.MediaType != manifestType || m.Config.MediaType != configType || m.Layers == nil || len(m.Layers) > 127 || !validAnnotations(m.Annotations) {
		return ErrInput
	}
	descriptors := append([]descriptor{m.Config}, m.Layers...)
	if len(descriptors) != len(q.Blobs) {
		return ErrInput
	}
	expected := make(map[string]int64, len(descriptors))
	for i, d := range descriptors {
		if !digestName.MatchString(d.Digest) || d.Size == nil || *d.Size < 0 || *d.Size > maxBlob || !validAnnotations(d.Annotations) {
			return ErrInput
		}
		if i > 0 && d.MediaType != layerType && d.MediaType != layerType+"+gzip" && d.MediaType != layerType+"+zstd" {
			return ErrInput
		}
		if _, ok := expected[d.Digest]; ok {
			return ErrInput
		}
		expected[d.Digest] = *d.Size
	}
	var total int64
	seen := make(map[string]bool, len(q.Blobs))
	for _, b := range q.Blobs {
		size, ok := expected[b.Digest]
		if !ok || seen[b.Digest] || b.Open == nil || b.Size != size || b.Size < 0 || b.Size > maxBlob {
			return ErrInput
		}
		total += b.Size
		if total > maxTotal {
			return ErrInput
		}
		seen[b.Digest] = true
	}
	// Validate every descriptor's bytes before the first network request.
	for _, b := range q.Blobs {
		if ctx.Err() != nil {
			return ErrInterrupted
		}
		r, err := b.Open()
		if err != nil || r == nil {
			if r != nil {
				r.Close()
			}
			return ErrInput
		}
		h := sha256.New()
		n, err := io.Copy(h, &contextReader{ctx: ctx, r: io.LimitReader(r, b.Size+1)})
		closeErr := r.Close()
		if ctx.Err() != nil {
			return ErrInterrupted
		}
		if err != nil || closeErr != nil || n != b.Size || "sha256:"+hex.EncodeToString(h.Sum(nil)) != b.Digest {
			return ErrIdentity
		}
	}
	return nil
}
func credentialOK(v *credentialref.Value) bool {
	b := v.Bytes()
	if len(b) == 0 || len(b) > 4096 {
		return false
	}
	for _, c := range b {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if r.ctx.Err() != nil {
		return 0, ErrInterrupted
	}
	return r.r.Read(p)
}

func (c *Client) Publish(ctx context.Context, q PublishRequest, v *credentialref.Value) (PublishReceipt, error) {
	out := PublishReceipt{}
	if ctx == nil {
		return out, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	if ctx.Err() != nil {
		return out, ErrInterrupted
	}
	if len(q.Manifest) > maxManifest || len(q.Blobs) > 128 {
		return out, ErrInput
	}
	q.Manifest = bytes.Clone(q.Manifest)
	q.Blobs = append([]Blob(nil), q.Blobs...)
	if err := c.validate(ctx, q, v); err != nil {
		return out, err
	}
	out = PublishReceipt{Repository: q.Repository, Digest: q.Digest, Stage: "validated"}
	prefix := "/v2/" + q.Repository
	for _, b := range q.Blobs {
		resp, err := c.request(ctx, q.Check, v, http.MethodHead, c.origin.String()+prefix+"/blobs/"+b.Digest, nil, "")
		if err != nil {
			return out, err
		}
		status := resp.StatusCode
		valid := singleHeader(resp, "Docker-Content-Digest") == b.Digest && resp.ContentLength == b.Size
		if err := finish(resp, 0); err != nil {
			return out, err
		}
		if status == http.StatusOK {
			if !valid {
				return out, ErrIdentity
			}
			continue
		}
		if status != http.StatusNotFound {
			return out, statusError(status)
		}
		if err := check(ctx, q.Check); err != nil {
			return out, err
		}
		out.Stage = "blob_upload_start_attempted"
		resp, err = c.request(ctx, q.Check, v, http.MethodPost, c.origin.String()+prefix+"/blobs/uploads/", nil, "")
		if err != nil {
			return out, err
		}
		status = resp.StatusCode
		location, locErr := c.location(singleHeader(resp, "Location"), prefix, b.Digest)
		if err := finish(resp, 4096); err != nil {
			return out, err
		}
		if status != http.StatusAccepted {
			return out, statusError(status)
		}
		if locErr != nil {
			return out, locErr
		}
		r, openErr := b.Open()
		if openErr != nil || r == nil {
			if r != nil {
				r.Close()
			}
			return out, ErrIdentity
		}
		stream := newStream(r, b.Size)
		if err := check(ctx, q.Check); err != nil {
			stream.Close()
			return out, err
		}
		out.Stage = "blob_upload_attempted"
		resp, err = c.request(ctx, q.Check, v, http.MethodPut, location, stream, "application/octet-stream")
		// HTTP transports may close request bodies asynchronously. Wait until their
		// ownership ends before inspecting the independent stream count/hash state.
		select {
		case <-stream.done:
		case <-ctx.Done():
			return out, ErrInterrupted
		}
		if err != nil {
			return out, err
		}
		status = resp.StatusCode
		valid = singleHeader(resp, "Docker-Content-Digest") == b.Digest
		finishErr := finish(resp, 4096)
		if !stream.valid(b.Digest) {
			return out, ErrIdentity
		}
		if finishErr != nil {
			return out, finishErr
		}
		if status != http.StatusCreated {
			return out, statusError(status)
		}
		if !valid {
			return out, ErrIdentity
		}
	}
	if err := check(ctx, q.Check); err != nil {
		return out, err
	}
	out.Stage = "manifest_put_attempted"
	target := c.origin.String() + prefix + "/manifests/" + q.Digest
	resp, err := c.request(ctx, q.Check, v, http.MethodPut, target, io.NopCloser(bytes.NewReader(q.Manifest)), manifestType)
	if err != nil {
		return out, err
	}
	status := resp.StatusCode
	valid := singleHeader(resp, "Docker-Content-Digest") == q.Digest
	if err := finish(resp, 4096); err != nil {
		return out, err
	}
	if status != http.StatusCreated {
		return out, statusError(status)
	}
	if !valid {
		return out, ErrIdentity
	}
	out.Stage = "manifest_put_acknowledged"
	resp, err = c.request(ctx, q.Check, v, http.MethodGet, target, nil, manifestType)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, statusError(resp.StatusCode)
	}
	if singleHeader(resp, "Docker-Content-Digest") != q.Digest || singleHeader(resp, "Content-Type") != manifestType {
		return out, ErrIdentity
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxManifest+1))
	if err != nil {
		return out, ErrUnavailable
	}
	if len(raw) > maxManifest || digestOf(raw) != q.Digest || !bytes.Equal(raw, q.Manifest) {
		return out, ErrIdentity
	}
	out.Stage = "manifest_verified"
	out.Verified = true
	return out, nil
}

func check(ctx context.Context, fn func() error) error {
	if ctx.Err() != nil {
		return ErrInterrupted
	}
	if fn == nil || fn() != nil {
		return ErrDenied
	}
	if ctx.Err() != nil {
		return ErrInterrupted
	}
	return nil
}
func (c *Client) request(ctx context.Context, fn func() error, v *credentialref.Value, method, target string, body io.ReadCloser, media string) (*http.Response, error) {
	closeBody := func() {
		if body != nil {
			body.Close()
		}
	}
	if err := check(ctx, fn); err != nil {
		closeBody()
		return nil, err
	}
	if !credentialOK(v) {
		closeBody()
		return nil, ErrDenied
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		closeBody()
		return nil, ErrInput
	}
	req.Close = true
	req.Header.Set("Authorization", "Bearer "+string(v.Bytes()))
	if media != "" {
		req.Header.Set("Content-Type", media)
		req.Header.Set("Accept", manifestType)
	}
	if body != nil {
		req.ContentLength = -1
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ErrInterrupted
		}
		return nil, ErrUnavailable
	}
	return resp, nil
}
func singleHeader(resp *http.Response, key string) string {
	values := resp.Header.Values(key)
	if len(values) != 1 {
		return ""
	}
	return values[0]
}
func finish(resp *http.Response, limit int64) error {
	defer resp.Body.Close()
	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return ErrUnavailable
	}
	if n > limit {
		return ErrIdentity
	}
	return nil
}
func statusError(status int) error {
	if status == 401 || status == 403 {
		return ErrDenied
	}
	return ErrUnavailable
}
func (c *Client) location(raw, prefix, digest string) (string, error) {
	if len(raw) == 0 || len(raw) > 4096 || strings.ContainsAny(raw, "\\\r\n") {
		return "", ErrIdentity
	}
	ref, err := url.Parse(raw)
	if err != nil || ref.RawPath != "" || (ref.Path != "" && path.Clean(ref.Path) != ref.Path) {
		return "", ErrIdentity
	}
	baseURL := *c.origin
	baseURL.Path = prefix + "/blobs/uploads/"
	u := baseURL.ResolveReference(ref)
	if u.Scheme != c.origin.Scheme || u.Host != c.origin.Host || u.User != nil || u.Fragment != "" || u.Opaque != "" || u.RawPath != "" || u.ForceQuery {
		return "", ErrIdentity
	}
	base := prefix + "/blobs/uploads/"
	if !strings.HasPrefix(u.Path, base) || !uploadID.MatchString(strings.TrimPrefix(u.Path, base)) {
		return "", ErrIdentity
	}
	values, err := url.ParseQuery(u.RawQuery)
	if err != nil || len(values) > 1 {
		return "", ErrIdentity
	}
	for key, vs := range values {
		if key != "_state" || len(vs) != 1 || len(vs[0]) > 2048 || !uploadState.MatchString(vs[0]) {
			return "", ErrIdentity
		}
	}
	values.Set("digest", digest)
	u.RawQuery = values.Encode()
	return u.String(), nil
}

// stream tracks actual transport reads independently of ContentLength and EOF
// interpretation. It never buffers blob contents. Reopened source drift denies
// manifest commit, including an early response before the body reaches EOF.
type stream struct {
	mu     sync.Mutex
	r      io.ReadCloser
	h      hash.Hash
	n, max int64
	eof    bool
	bad    bool
	closed bool
	done   chan struct{}
}

func newStream(r io.ReadCloser, size int64) *stream {
	return &stream{r: r, h: sha256.New(), max: size, done: make(chan struct{})}
}
func (s *stream) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, io.ErrClosedPipe
	}
	remaining := s.max - s.n + 1
	if remaining <= 0 {
		return 0, ErrIdentity
	}
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}
	s.mu.Unlock()
	n, err := s.r.Read(p)
	s.mu.Lock()
	s.n += int64(n)
	s.h.Write(p[:n])
	if err == io.EOF {
		s.eof = true
	} else if err != nil {
		s.bad = true
	}
	if s.n > s.max {
		s.bad = true
		return n, ErrIdentity
	}
	return n, err
}
func (s *stream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	err := s.r.Close()
	if err != nil {
		s.bad = true
	}
	close(s.done)
	return err
}
func (s *stream) valid(digest string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed && !s.bad && s.eof && s.n == s.max && "sha256:"+hex.EncodeToString(s.h.Sum(nil)) == digest
}

package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/servicerecovery"
)

// verifyRestoredRegistry tests real authenticated immutable-manifest pull and
// rejects a mutation request with that read-only identity. No blob/tag is created.
// Unknown routes/challenges/permissions remain blocked rather than claimed passed.
func verifyRestoredRegistry(ctx context.Context, p generated.ServiceRecoveryProfile, transport http.RoundTripper, key *credentialref.Value) (string, error) {
	origin, e := url.Parse(p.HarborOrigin)
	if e != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || origin.Path != "" && origin.Path != "/" {
		return "", servicerecovery.Invalid()
	}
	if transport == nil {
		transport = &http.Transport{Proxy: nil, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second}
	}
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	repo := p.HarborProject + "/" + p.HarborRepository
	tokenURL := strings.TrimRight(p.HarborOrigin, "/") + "/service/token?service=harbor-registry&scope=" + url.QueryEscape("repository:"+repo+":pull")
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
	if e != nil {
		return "", servicerecovery.Invalid()
	}
	req.SetBasicAuth(p.HarborUsername, string(key.Bytes()))
	res, e := client.Do(req)
	if e != nil {
		return "", servicerecovery.Blocked()
	}
	raw, e := io.ReadAll(io.LimitReader(res.Body, 65537))
	_ = res.Body.Close()
	if e != nil || res.StatusCode != 200 || len(raw) > 65536 {
		return "", servicerecovery.Blocked()
	}
	var token struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if json.Unmarshal(raw, &token) != nil {
		return "", servicerecovery.Blocked()
	}
	if token.Token == "" {
		token.Token = token.AccessToken
	}
	if token.Token == "" || len(token.Token) > 16384 {
		return "", servicerecovery.Blocked()
	}
	manifestURL := strings.TrimRight(p.HarborOrigin, "/") + "/v2/" + repo + "/manifests/" + p.HarborArtifactDigest
	req, e = http.NewRequestWithContext(ctx, http.MethodGet, manifestURL, nil)
	if e != nil {
		return "", servicerecovery.Invalid()
	}
	req.Header.Set("Authorization", "Bearer "+token.Token)
	req.Header.Set("Accept", "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json")
	res, e = client.Do(req)
	if e != nil {
		return "", servicerecovery.Blocked()
	}
	raw, e = io.ReadAll(io.LimitReader(res.Body, (4<<20)+1))
	_ = res.Body.Close()
	sum := sha256.Sum256(raw)
	if e != nil || res.StatusCode != 200 || len(raw) > 4<<20 || "sha256:"+hex.EncodeToString(sum[:]) != p.HarborArtifactDigest {
		return "", servicerecovery.Blocked()
	}
	// Pull the complete configured image, including config and every layer, and
	// authenticate actual blob bytes rather than merely trusting artifact metadata.
	var image struct {
		SchemaVersion int `json:"schemaVersion"`
		Config        struct {
			Digest string `json:"digest"`
			Size   int64  `json:"size"`
		} `json:"config"`
		Layers []struct {
			Digest string `json:"digest"`
			Size   int64  `json:"size"`
		} `json:"layers"`
	}
	if json.Unmarshal(raw, &image) != nil || image.SchemaVersion != 2 || image.Config.Size < 1 || len(image.Config.Digest) != 71 || len(image.Layers) > 128 {
		return "", servicerecovery.Blocked()
	}
	remaining := p.MaximumBytes
	blobs := append(image.Layers, image.Config)
	for _, blob := range blobs {
		if blob.Size < 0 || blob.Size > remaining || !strings.HasPrefix(blob.Digest, "sha256:") || len(blob.Digest) != 71 {
			return "", servicerecovery.Blocked()
		}
		remaining -= blob.Size
		request, e := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(p.HarborOrigin, "/")+"/v2/"+repo+"/blobs/"+blob.Digest, nil)
		if e != nil {
			return "", servicerecovery.Invalid()
		}
		request.Header.Set("Authorization", "Bearer "+token.Token)
		response, e := client.Do(request)
		if e != nil {
			return "", servicerecovery.Blocked()
		}
		hash := sha256.New()
		n, readErr := io.Copy(hash, io.LimitReader(response.Body, blob.Size+1))
		_ = response.Body.Close()
		if readErr != nil || response.StatusCode != 200 || n != blob.Size || "sha256:"+hex.EncodeToString(hash.Sum(nil)) != blob.Digest {
			return "", servicerecovery.Blocked()
		}
	}
	// A token with pull-only scope must be denied before starting an upload. If
	// the server unexpectedly permits it, retain the uncommitted UUID as unknown
	// provider state; never upload bytes or attempt destructive cleanup.
	req, e = http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(p.HarborOrigin, "/")+"/v2/"+repo+"/blobs/uploads/", nil)
	if e != nil {
		return "", servicerecovery.Invalid()
	}
	req.Header.Set("Authorization", "Bearer "+token.Token)
	res, e = client.Do(req)
	if e != nil {
		return "", servicerecovery.Blocked()
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 16384))
	_ = res.Body.Close()
	if res.StatusCode != 401 && res.StatusCode != 403 {
		return "", servicerecovery.Blocked()
	}
	return servicerecovery.Digest([]string{p.HarborArtifactDigest, "authenticated-complete-image-pull", "pull-token-upload-denied"}), nil
}

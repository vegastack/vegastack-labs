package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestServiceRecoveryRegistryPullAndDenial(t *testing.T) {
	config := []byte(`{"architecture":"arm64","os":"linux"}`)
	layer := []byte("isolated-restored-image-layer")
	hash := func(b []byte) string { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }
	configDigest, layerDigest := hash(config), hash(layer)
	manifest, _ := json.Marshal(map[string]any{"schemaVersion": 2, "config": map[string]any{"digest": configDigest, "size": len(config)}, "layers": []any{map[string]any{"digest": layerDigest, "size": len(layer)}}})
	digest := hash(manifest)
	for _, fault := range []string{"none", "corrupt-layer", "upload-permitted", "wrong-manifest"} {
		t.Run(fault, func(t *testing.T) {
			pulls := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/service/token":
					u, p, ok := r.BasicAuth()
					if !ok || u != "robot$fixture" || p != "fixture-key" {
						t.Error("credentials not exact")
						w.WriteHeader(401)
						return
					}
					_, _ = w.Write([]byte(`{"token":"fixture-token"}`))
				case "/v2/project/image/manifests/" + digest:
					if fault == "wrong-manifest" {
						_, _ = w.Write([]byte("changed"))
					} else {
						_, _ = w.Write(manifest)
					}
				case "/v2/project/image/blobs/" + configDigest:
					pulls++
					_, _ = w.Write(config)
				case "/v2/project/image/blobs/" + layerDigest:
					pulls++
					if fault == "corrupt-layer" {
						_, _ = w.Write([]byte("corrupt"))
					} else {
						_, _ = w.Write(layer)
					}
				case "/v2/project/image/blobs/uploads/":
					if fault == "upload-permitted" {
						w.WriteHeader(202)
					} else {
						w.WriteHeader(403)
					}
				default:
					t.Errorf("unexpected registry route %s", r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			key, _ := credentialref.NewValue([]byte("fixture-key"))
			defer key.Close()
			p := generated.ServiceRecoveryProfile{HarborOrigin: server.URL, HarborProject: "project", HarborRepository: "image", HarborArtifactDigest: digest, HarborUsername: "robot$fixture", MaximumBytes: 1 << 20}
			proof, e := verifyRestoredRegistry(context.Background(), p, server.Client().Transport, key)
			if fault == "none" {
				if e != nil || proof == "" || pulls != 2 {
					t.Fatalf("real full image pull denied: %s %v pulls=%d", proof, e, pulls)
				}
			} else if e == nil {
				t.Fatalf("unsafe registry behavior accepted: %s", fault)
			}
		})
	}
}

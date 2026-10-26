//go:build linux

package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/servicecatalog"
)

func TestServiceDeploymentCompositionProtectedArtifactFailsWithoutTrust(t *testing.T) {
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	manifest := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{},"layers":[]}`)
	sum := sha256.Sum256(manifest)
	source := generated.ServiceDeploymentArtifactSource{ArtifactID: "image-a", Repository: "registry.example/project/app", Digest: "sha256:" + hex.EncodeToString(sum[:]), ManifestPath: filepath.Join(dir, "manifest"), BundlePath: filepath.Join(dir, "bundle"), PolicyPath: filepath.Join(dir, "policy")}
	for path, body := range map[string][]byte{source.ManifestPath: manifest, source.BundlePath: []byte(`{"private":"fixture-never-log"}`), source.PolicyPath: []byte(`{}`)} {
		if e := os.WriteFile(path, body, 0600); e != nil {
			t.Fatal(e)
		}
	}
	// Manifest bytes match the selected immutable digest, but no signed proof or
	// trusted policy is available. Actual protected reads and offline verification
	// must reject this without synthesizing artifact proof.
	for _, mode := range []string{"missing-trust", "changed-bytes", "unsafe-mode", "symlink"} {
		t.Run(mode, func(t *testing.T) {
			current := source
			switch mode {
			case "changed-bytes":
				current.Digest = servicecatalog.Digest("other bytes")
			case "unsafe-mode":
				if e := os.Chmod(source.ManifestPath, 0644); e != nil {
					t.Fatal(e)
				}
				defer os.Chmod(source.ManifestPath, 0600)
			case "symlink":
				current.ManifestPath = filepath.Join(dir, "manifest-link")
				if e := os.Symlink(source.ManifestPath, current.ManifestPath); e != nil {
					t.Fatal(e)
				}
			}
			sealed, e := deploymentArtifact(context.Background(), current, uint32(os.Geteuid()))
			if e == nil || sealed != (generated.ServiceDeploymentArtifact{}) {
				t.Fatal("unsigned or unsafe bytes sealed", sealed, e)
			}
			if strings.Contains(e.Error(), "fixture-never-log") {
				t.Fatal("private file content escaped error")
			}
		})
	}
}

func TestServiceDeploymentCompositionMissingCapabilitiesNeverBorrows(t *testing.T) {
	f := newServiceCatalogWorkflow(t)
	f.register()
	for _, x := range []struct{ reference, consumer, purpose, capability string }{{"hosting-ref", "hosting.coolify.deploy", "hosting-deploy", "credential.hosting.deploy"}, {"registry-ref", "service.runtime", "runtime-observe", "credential.service-runtime.read"}} {
		value, _, e := f.source.borrow(f.ctx, f.definition, false, 0, x.reference, x.consumer, x.purpose, x.capability)
		if e == nil || value != nil || len(f.resolver.values) != 0 || f.hostingCalls.Load() != 0 || f.artifactCalls.Load() != 0 {
			t.Fatal("missing deployment capability borrowed/contacted provider", value, e)
		}
	}
	// A catalog registration and observation profile provide no role admission.
	_, e := (hostReplacementComposition{gates: f.source.gates, clock: time.Now}).roleAdmission(f.ctx, f.definition.HostID)
	if e == nil || f.hostingCalls.Load() != 0 || f.artifactCalls.Load() != 0 {
		t.Fatal("registration treated as workload admission", e)
	}
}

func TestServiceDeploymentCompositionRegistryOutageClosesBorrow(t *testing.T) {
	f := newServiceCatalogWorkflow(t)
	f.register()
	f.artifactUnavailable = true
	binding, e := f.source.binding(f.definition)
	if e != nil {
		t.Fatal(e)
	}
	snapshot, _, e := f.source.artifact(f.ctx, f.definition, false, 0, *binding.Harbor)
	if e == nil || snapshot.Digest != "" || f.artifactCalls.Load() != 1 || f.hostingCalls.Load() != 0 {
		t.Fatal("registry outage became deployment artifact", snapshot, e)
	}
	if strings.Contains(e.Error(), "fixture-service-secret") {
		t.Fatal("provider secret escaped")
	}
	f.closed()
}

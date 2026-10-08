//go:build linux

package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/adapter/nativecredential"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"golang.org/x/crypto/ssh"
)

func TestPreloadedDiscoveryProtectedKeyFiles(t *testing.T) {
	for _, scenario := range []string{"valid", "changed-key", "missing", "oversized", "malformed", "encrypted", "file-symlink", "directory-symlink", "file-directory", "loose-file", "loose-directory", "wrong-owner", "wrong-mode", "legacy-mode", "missing-digest", "relative-directory", "unclean-directory", "cancelled", "wrong-version"} {
		t.Run(scenario, func(t *testing.T) {
			directory := t.TempDir()
			if err := os.Chmod(directory, 0700); err != nil {
				t.Fatal(err)
			}
			raw, signer := preloadedReaderSyntheticKey(t)
			sum := sha256.Sum256(signer.PublicKey().Marshal())
			digest, mode := "sha256:"+hex.EncodeToString(sum[:]), "preloaded-discovery"
			target := hostdiscovery.Target{Binding: generated.HostDiscoveryTarget{Schema: generated.SchemaIDHostDiscoveryTarget, SchemaVersion: "1.0.0", TargetID: "synthetic", Revision: 1, Address: "127.0.0.1", Port: 2222, User: "inspect", HostKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))), ProfileID: "debian-13", CredentialReferenceID: "synthetic-key", MaterialVersion: "v1", ExpectedOS: "debian", ExpectedVersion: "13", ExpectedArchitecture: "amd64", CredentialMode: &mode, CredentialPublicKeyDigest: &digest}}
			path := filepath.Join(directory, nativecredential.LoadedNameForVersion(hostdiscovery.Consumer, target.Binding.CredentialReferenceID, target.Binding.MaterialVersion))
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			owner := uint32(os.Getuid())
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			switch scenario {
			case "changed-key":
				other, _ := preloadedReaderSyntheticKey(t)
				must(os.WriteFile(path, other, 0600))
			case "missing":
				must(os.Remove(path))
			case "oversized":
				must(os.WriteFile(path, bytes.Repeat([]byte("x"), 4097), 0600))
			case "malformed":
				must(os.WriteFile(path, []byte("not a private key"), 0600))
			case "encrypted":
				_, private, err := ed25519.GenerateKey(rand.Reader)
				must(err)
				block, err := ssh.MarshalPrivateKeyWithPassphrase(private, "", []byte("synthetic-only"))
				must(err)
				must(os.WriteFile(path, pem.EncodeToMemory(block), 0600))
			case "file-symlink":
				must(os.Rename(path, path+"-actual"))
				must(os.Symlink(path+"-actual", path))
			case "directory-symlink":
				link := filepath.Join(t.TempDir(), "link")
				must(os.Symlink(directory, link))
				directory = link
			case "file-directory":
				must(os.Remove(path))
				must(os.Mkdir(path, 0700))
			case "loose-file":
				must(os.Chmod(path, 0644))
			case "loose-directory":
				must(os.Chmod(directory, 0755))
			case "wrong-owner":
				owner++
			case "wrong-mode":
				mode = "mutation"
			case "legacy-mode":
				target.Binding.CredentialMode = nil
			case "missing-digest":
				target.Binding.CredentialPublicKeyDigest = nil
			case "relative-directory":
				directory = "relative"
			case "unclean-directory":
				directory += "/."
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "wrong-version":
				target.Binding.MaterialVersion = "v2"
			}
			t.Setenv("CREDENTIALS_DIRECTORY", directory)
			value, err := newPreloadedDiscoveryKeyReader(owner).Borrow(ctx, target)
			if scenario != "valid" {
				if value != nil {
					value.Close()
					t.Fatal("denial returned credential")
				}
				if err == nil {
					t.Fatal("invalid credential accepted")
				}
				if strings.Contains(err.Error(), directory) || strings.Contains(err.Error(), string(raw)) {
					t.Fatal("denial exposed private material or path")
				}
				return
			}
			if err != nil || value == nil {
				t.Fatalf("valid protected key denied: %v", err)
			}
			borrowed := value.Bytes()
			if !bytes.Equal(raw, borrowed) {
				t.Fatal("borrowed value differs from supplied material")
			}
			value.Close()
			if len(value.Bytes()) != 0 || !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
				t.Fatal("close did not clear borrowed material")
			}
		})
	}
}

func preloadedReaderSyntheticKey(t *testing.T) ([]byte, ssh.Signer) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(private, "")
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block), signer
}

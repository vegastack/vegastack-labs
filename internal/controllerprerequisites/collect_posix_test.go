//go:build linux || darwin

package controllerprerequisites

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testMachine = "00000000000000000000000000000001"

func put(t *testing.T, root, path, content string) {
	t.Helper()
	full := filepath.Join(root, path)
	if e := os.MkdirAll(filepath.Dir(full), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(full, []byte(content), 0600); e != nil {
		t.Fatal(e)
	}
}
func setup(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	put(t, root, "/etc/machine-id", testMachine+"\n")
	put(t, root, "/etc/passwd", "vsk-labs:x:1234:1235::/var/lib/vsk-labs:/usr/sbin/nologin\n")
	put(t, root, "/etc/vsk-labs/control/server.json", `{"remoteRead":{"enabled":false}}`)
	return root
}
func find(t *testing.T, d generated.ControllerPrerequisitesData, name string) generated.ControllerPrerequisiteFact {
	t.Helper()
	for _, f := range d.Facts {
		if f.Selector == name {
			return f
		}
	}
	t.Fatal("missing fact", name)
	return generated.ControllerPrerequisiteFact{}
}
func TestIdentityDeniesBeforeControllerReads(t *testing.T) {
	root := setup(t)
	for _, id := range []string{"invalid", strings.Repeat("f", 32)} {
		d := collectRoot(context.Background(), id, root)
		if d.IdentityMatched || len(d.Facts) != 0 {
			t.Fatal("mismatched identity collected metadata")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if collectRoot(ctx, testMachine, root).IdentityMatched {
		t.Fatal("cancelled collection")
	}
}
func TestFiniteFactsDoNotExposeCredentialMaterial(t *testing.T) {
	root := setup(t)
	put(t, root, "/etc/vsk-labs/native-credential-authority.json", "SECRET_POLICY_CONTENT")
	put(t, root, "/var/lib/vsk-labs/control/credential-drafts/credential-secret", "SECRET_CIPHERTEXT")
	put(t, root, "/etc/vsk-labs/control/credentials/slack-bot-token", "SECRET_TOKEN")
	d := collectRoot(context.Background(), testMachine, root)
	if !d.IdentityMatched || d.AdmissionQualified || len(d.Facts) != 9 {
		t.Fatalf("bad facts %#v", d)
	}
	if f := find(t, d, "account"); f.UID != "1234" || f.GID != "1235" {
		t.Fatal("wrong canonical account", f)
	}
	if find(t, d, "unit").State != "missing" || find(t, d, "custody-policy").State != "present" || find(t, d, "tls-certificate").State != "disabled" {
		t.Fatal("presence contract")
	}
	raw, _ := json.Marshal(d)
	if strings.Contains(string(raw), "SECRET_") {
		t.Fatal("secret disclosure")
	}
	if generated.ValidateContractJSON(generated.SchemaIDControllerPrerequisitesData, raw, generated.ContractExact) != nil {
		t.Fatal("invalid result contract")
	}
}
func TestRejectSymlinkAndUnboundedFile(t *testing.T) {
	root := setup(t)
	put(t, root, "/outside", "SECRET")
	path := filepath.Join(root, "/etc/systemd/system")
	os.MkdirAll(path, 0700)
	if e := os.Symlink(filepath.Join(root, "outside"), filepath.Join(path, "vsk-labs.service")); e != nil {
		t.Fatal(e)
	}
	if find(t, collectRoot(context.Background(), testMachine, root), "unit").State != "unsafe" {
		t.Fatal("symlink accepted")
	}
	if _, _, e := readFixed(context.Background(), root, "/outside", 2); e == nil {
		t.Fatal("unbounded file accepted")
	}
	if _, _, e := readFixed(context.Background(), root, "/absent", 20); !os.IsNotExist(e) {
		t.Fatal("missing status lost")
	}
}
func TestPublicTLSAndPrivatePathDenial(t *testing.T) {
	root := setup(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "controller.invalid"}, DNSNames: []string{"controller.invalid"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, e := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	put(t, root, "/etc/vsk-labs/control/tls/server.crt", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	put(t, root, "/etc/vsk-labs/control/server.json", `{"remoteRead":{"enabled":true,"tlsCertificatePath":"/etc/vsk-labs/control/tls/server.crt","tlsPrivateKeyPath":"/must-not-read"}}`)
	f := find(t, collectRoot(context.Background(), testMachine, root), "tls-certificate")
	if f.State != "present" || f.Digest != digest(der) || f.DNSNames != "controller.invalid" {
		t.Fatal("bad TLS facts", f)
	}
	put(t, root, "/etc/vsk-labs/control/server.json", `{"remoteRead":{"enabled":true,"tlsCertificatePath":"/etc/vsk-labs/control/credentials/slack-bot-token"}}`)
	if find(t, collectRoot(context.Background(), testMachine, root), "tls-certificate").State != "unsafe" {
		t.Fatal("noncertificate path accepted")
	}
}

func TestUnreadableCanonicalFileRemainsUnavailable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read mode-zero files")
	}
	root := setup(t)
	put(t, root, "/etc/systemd/system/vsk-labs.service", "nonsecret-unit")
	if e := os.Chmod(filepath.Join(root, "/etc/systemd/system/vsk-labs.service"), 0); e != nil {
		t.Fatal(e)
	}
	if find(t, collectRoot(context.Background(), testMachine, root), "unit").State != "unavailable" {
		t.Fatal("unreadable unit did not remain unavailable")
	}
}

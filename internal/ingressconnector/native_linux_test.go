//go:build linux

package ingressconnector

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func nativeFixture(t *testing.T) (*native, *int, *int) {
	t.Helper()
	root := t.TempDir()
	for _, p := range []string{"etc/systemd/system", "etc/vsk-labs/ingress", "usr/local/bin"} {
		if e := os.MkdirAll(filepath.Join(root, p), 0755); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.WriteFile(filepath.Join(root, strings.TrimPrefix(TokenPath, "/")), syntheticToken(fixtureInput()), 0600); e != nil {
		t.Fatal(e)
	}
	starts, fetches := 0, 0
	n := &native{root: root, uid: uint32(os.Geteuid()), binaryDigest: hash([]byte("synthetic-pinned-binary")), process: func(int64) error { return nil }}
	n.fetch = func(_ context.Context, w io.Writer) error {
		fetches++
		_, e := io.WriteString(w, "synthetic-pinned-binary")
		return e
	}
	n.run = func(_ context.Context, args []string) ([]byte, error) {
		switch args[0] {
		case "list-units", "list-unit-files":
			return nil, nil
		case "start":
			starts++
		case "show":
			return []byte("ActiveState=active\nSubState=running\nMainPID=123\nFragmentPath=" + UnitPath + "\nDropInPaths=\nDynamicUser=yes\n"), nil
		}
		return nil, nil
	}
	return n, &starts, &fetches
}
func TestNativeExactInstallationAndRepeat(t *testing.T) {
	n, starts, fetches := nativeFixture(t)
	v, e := n.Install(context.Background(), fixtureInput())
	if e != nil || !v.Changed || !v.Verified || *starts != 1 || *fetches != 1 {
		t.Fatal(v, e, *starts, *fetches)
	}
	raw, e := os.ReadFile(n.path(UnitPath))
	if e != nil || string(raw) != string(Unit(fixtureInput())) || strings.Contains(string(raw), "synthetic-token") {
		t.Fatal("unit contents", e)
	}
	v, e = n.Install(context.Background(), fixtureInput())
	if e != nil || !v.Verified || *fetches != 1 {
		t.Fatal("same owned installation retry", v, e, *fetches)
	}
}
func TestNativeDeniesUnsafeArtifactsBeforeStart(t *testing.T) {
	for _, fault := range []string{"missing-token", "token-mode", "token-symlink", "token-hardlink", "parent-writable", "wrong-owner", "conflicting-unit", "dropin", "binary-drift", "download-drift", "ca-missing", "unexpected-running-unit", "wrong-token-account", "wrong-token-tunnel", "malformed-token", "unknown-token-field", "alternate-token-endpoint"} {
		t.Run(fault, func(t *testing.T) {
			n, starts, _ := nativeFixture(t)
			in := fixtureInput()
			switch fault {
			case "wrong-token-account", "wrong-token-tunnel", "malformed-token", "unknown-token-field", "alternate-token-endpoint":
				other := in
				if fault == "wrong-token-account" {
					other.AccountID = strings.Repeat("b", 32)
				}
				if fault == "wrong-token-tunnel" {
					other.TunnelID = "22222222-2222-2222-2222-222222222222"
				}
				token := syntheticToken(other)
				if fault == "malformed-token" {
					token = []byte("not-base64")
				}
				if fault == "unknown-token-field" || fault == "alternate-token-endpoint" {
					v := map[string]any{"a": in.AccountID, "t": in.TunnelID, "s": make([]byte, 32)}
					if fault == "unknown-token-field" {
						v["extra"] = true
					} else {
						v["e"] = "unselected.example"
					}
					raw, _ := json.Marshal(v)
					token = []byte(base64.StdEncoding.EncodeToString(raw))
				}
				os.WriteFile(n.path(TokenPath), token, 0600)

			case "missing-token":
				os.Remove(n.path(TokenPath))
			case "token-mode":
				os.Chmod(n.path(TokenPath), 0644)
			case "token-symlink":
				os.Remove(n.path(TokenPath))
				os.Symlink("/dev/null", n.path(TokenPath))
			case "token-hardlink":
				os.Link(n.path(TokenPath), n.path(TokenPath)+"-alias")
			case "parent-writable":
				os.Chmod(n.path("/etc/vsk-labs/ingress"), 0777)
			case "wrong-owner":
				n.uid++
			case "conflicting-unit":
				os.WriteFile(n.path(UnitPath), []byte("unrelated service"), 0644)
			case "dropin":
				os.Mkdir(n.path(UnitPath+".d"), 0755)
			case "binary-drift":
				os.WriteFile(n.path(BinaryPath), []byte("unrelated binary"), 0755)
			case "download-drift":
				n.binaryDigest = strings.Repeat("0", 64)
			case "ca-missing":
				in.OriginCADigest = "sha256:" + strings.Repeat("a", 64)
			case "unexpected-running-unit":
				old := n.run
				n.run = func(c context.Context, a []string) ([]byte, error) {
					if a[0] == "list-units" {
						return []byte(UnitName + " loaded active running other"), nil
					}
					return old(c, a)
				}
			}
			v, e := n.Install(context.Background(), in)
			if e == nil || v.Verified || *starts != 0 {
				t.Fatal("unsafe install reached start", fault, v, e, *starts)
			}
		})
	}
}
func TestNativePartialFailureDoesNotQualify(t *testing.T) {
	for _, fault := range []string{"start-failed", "wrong-process", "wrong-unit-observation"} {
		t.Run(fault, func(t *testing.T) {
			n, _, _ := nativeFixture(t)
			old := n.run
			n.run = func(c context.Context, a []string) ([]byte, error) {
				if fault == "start-failed" && a[0] == "start" {
					return nil, denied()
				}
				if fault == "wrong-unit-observation" && a[0] == "show" {
					return []byte("ActiveState=active\nMainPID=123\nFragmentPath=/tmp/unowned.service\n"), nil
				}
				return old(c, a)
			}
			if fault == "wrong-process" {
				n.process = func(int64) error { return denied() }
			}
			v, e := n.Install(context.Background(), fixtureInput())
			if e == nil || !v.Changed || v.Verified {
				t.Fatal(v, e)
			}
		})
	}
}

func TestNativeCARequiresOnlyPinnedValidPublicCA(t *testing.T) {
	n, starts, _ := nativeFixture(t)
	public, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if e != nil {
		t.Fatal(e)
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	in := fixtureInput()
	in.OriginCADigest = "sha256:" + hash(ca)
	if e = os.WriteFile(n.path(CAPath), ca, 0644); e != nil {
		t.Fatal(e)
	}
	v, e := n.Install(context.Background(), in)
	if e != nil || !v.Verified || *starts != 1 {
		t.Fatal(v, e)
	}
	for _, bad := range [][]byte{append(append([]byte{}, ca...), []byte("unexpected bytes")...), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("synthetic-not-a-key")})} {
		n, starts, _ := nativeFixture(t)
		in.OriginCADigest = "sha256:" + hash(bad)
		os.WriteFile(n.path(CAPath), bad, 0644)
		v, e := n.Install(context.Background(), in)
		if e == nil || v.Verified || *starts != 0 {
			t.Fatal("non-CA trust material accepted", v, e)
		}
	}
}

func syntheticToken(in Input) []byte {
	raw, _ := json.Marshal(map[string]any{"a": in.AccountID, "s": []byte(strings.Repeat("x", 32)), "t": in.TunnelID})
	return []byte(base64.StdEncoding.EncodeToString(raw))
}

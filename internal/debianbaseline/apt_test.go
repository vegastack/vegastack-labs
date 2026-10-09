//go:build linux || darwin

package debianbaseline

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func aptFixture(t *testing.T) (*nativeRuntime, func(string, []byte)) {
	t.Helper()
	root := t.TempDir()
	write := func(p string, b []byte) {
		t.Helper()
		full := filepath.Join(root, p)
		if e := os.MkdirAll(filepath.Dir(full), 0700); e != nil {
			t.Fatal(e)
		}
		if strings.HasSuffix(p, "_InRelease") {
			b = append([]byte("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n"), append(b, []byte("\n-----BEGIN PGP SIGNATURE-----\nsynthetic\n-----END PGP SIGNATURE-----\n")...)...)
		}
		if e := os.WriteFile(full, b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	fingerprint := strings.Repeat("A", 40)
	packages := []byte("Package: auditd\nVersion: fixture\n\n")
	cfg := aptPreparedSources{Owner: "operator", SoakSeconds: 604800, Sources: []aptPreparedSource{{SourceFile: "snapshot.sources", ReleaseFile: "snapshot_InRelease", KeyringFile: "debian.gpg", Fingerprint: fingerprint, Kind: "snapshot", PackagesFile: "snapshot_Packages", PackagesReleasePath: "main/binary-amd64/Packages"}, {SourceFile: "security.sources", ReleaseFile: "security_InRelease", KeyringFile: "debian.gpg", Fingerprint: fingerprint, Kind: "security"}}}
	raw, _ := json.Marshal(cfg)
	write("etc/vsk-labs/baseline/apt-sources.json", raw)
	lock := generated.DebianProfileLock{Packages: []generated.AccessPackage{{Name: "auditd", Version: "fixture"}}}
	raw, _ = json.Marshal(lock)
	write("etc/vsk-labs/debian-profile.json", raw)
	for _, s := range cfg.Sources {
		write("etc/apt/sources.list.d/"+s.SourceFile, []byte("Types: deb\nURIs: https://fixture.invalid/debian\nSuites: trixie\nSigned-By: /usr/share/keyrings/debian.gpg\n"))
	}
	write("usr/share/keyrings/debian.gpg", []byte("synthetic keyring, verifier OS seam substituted"))
	write("var/lib/apt/lists/snapshot_Packages", packages)
	write("var/lib/apt/lists/snapshot_InRelease", []byte("Date: "+now.Add(-8*24*time.Hour).Format(time.RFC1123Z)+"\nValid-Until: "+now.Add(24*time.Hour).Format(time.RFC1123Z)+"\nSHA256:\n "+strings.TrimPrefix(digestBytes(packages), "sha256:")+" 39 main/binary-amd64/Packages\n"))
	write("var/lib/apt/lists/security_InRelease", []byte("Date: "+now.Add(-time.Hour).Format(time.RFC1123Z)+"\nValid-Until: "+now.Add(24*time.Hour).Format(time.RFC1123Z)+"\n"))
	n := &nativeRuntime{root: root, now: func() time.Time { return now }, run: func(_ context.Context, bin string, _ []string, _ []byte) ([]byte, error) {
		if bin == "/usr/bin/systemctl" {
			return []byte("LoadState=loaded\nActiveState=inactive\n"), nil
		}
		if bin == "/usr/bin/apt-config" {
			return []byte("APT::Periodic::Enable \"0\";\n"), nil
		}
		if bin == "/usr/bin/gpgv" {
			return []byte("[GNUPG:] VALIDSIG " + fingerprint + " actual-native-command-boundary-fixture"), nil
		}
		return nil, errBaseline
	}}
	return n, write
}
func TestUpdateProofRequiresActualSignedSnapshotPackageJoin(t *testing.T) {
	n, write := aptFixture(t)
	raw, e := n.readAPT(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	var got updateObservation
	json.Unmarshal(raw, &got)
	if !got.SignatureVerified || got.SoakSeconds < 604800 || got.SignedAt.IsZero() {
		t.Fatal("missing actual joined observations", got)
	}
	write("var/lib/apt/lists/snapshot_Packages", []byte("Package: auditd\nVersion: attacker\n\n"))
	if _, e = n.readAPT(context.Background()); e == nil {
		t.Fatal("unsigned replacement package metadata passed")
	}
}
func TestUpdateProofRejectsUnknownEnabledSource(t *testing.T) {
	n, write := aptFixture(t)
	write("etc/apt/sources.list.d/unknown.list", []byte("deb [trusted=yes] https://fixture.invalid other main\n"))
	if _, e := n.readAPT(context.Background()); e == nil {
		t.Fatal("unsigned extra source ignored")
	}
}

func TestSignedReleaseParserRejectsUnsignedTrailer(t *testing.T) {
	raw := []byte("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nDate: signed\n-----BEGIN PGP SIGNATURE-----\nfixture\n-----END PGP SIGNATURE-----\nDate: unsigned\n")
	if _, e := signedReleasePayload(raw); e == nil {
		t.Fatal("unsigned trailer treated as authenticated metadata")
	}
}

func TestStableSnapshotMissingExpiryDoesNotRelaxSecurityFreshness(t *testing.T) {
	for _, mode := range []string{"stable-no-expiry", "expired-snapshot", "security-no-expiry", "old-security"} {
		t.Run(mode, func(t *testing.T) {
			n, _ := aptFixture(t)
			p := filepath.Join(n.root, "var/lib/apt/lists/snapshot_InRelease")
			raw, e := os.ReadFile(p)
			if e != nil {
				t.Fatal(e)
			}
			lines := strings.Split(string(raw), "\n")
			kept := []string{}
			for _, line := range lines {
				if !strings.HasPrefix(line, "Valid-Until:") {
					kept = append(kept, line)
				}
			}
			raw = []byte(strings.Join(kept, "\n"))
			if mode == "expired-snapshot" {
				raw = []byte(strings.Replace(string(raw), "SHA256:", "Valid-Until: "+n.now().Add(-time.Hour).Format(time.RFC1123Z)+"\nSHA256:", 1))
			}
			os.WriteFile(p, raw, 0600)
			if mode == "security-no-expiry" || mode == "old-security" {
				p = filepath.Join(n.root, "var/lib/apt/lists/security_InRelease")
				raw, _ = os.ReadFile(p)
				lines = strings.Split(string(raw), "\n")
				kept = nil
				for _, line := range lines {
					if mode == "security-no-expiry" && strings.HasPrefix(line, "Valid-Until:") {
						continue
					}
					if mode == "old-security" && strings.HasPrefix(line, "Date:") {
						line = "Date: " + n.now().Add(-25*time.Hour).Format(time.RFC1123Z)
					}
					kept = append(kept, line)
				}
				os.WriteFile(p, []byte(strings.Join(kept, "\n")), 0600)
			}
			_, e = n.readAPT(context.Background())
			if mode == "stable-no-expiry" && e != nil {
				t.Fatal("official stable format rejected", e)
			}
			if mode != "stable-no-expiry" && e == nil {
				t.Fatal("expired or stale signed provenance accepted", mode)
			}
		})
	}
}

func TestUpdateOwnerRequiresAvailableAndActiveObservation(t *testing.T) {
	for _, mode := range []string{"unavailable", "inactive-unattended", "disabled-unattended", "active-unattended"} {
		t.Run(mode, func(t *testing.T) {
			n := &nativeRuntime{run: func(_ context.Context, bin string, args []string, _ []byte) ([]byte, error) {
				if mode == "unavailable" {
					return nil, errBaseline
				}
				if bin == "/usr/bin/systemctl" {
					state := "active"
					if mode == "inactive-unattended" {
						state = "inactive"
					}
					return []byte("LoadState=loaded\nActiveState=" + state + "\n"), nil
				}
				if mode == "disabled-unattended" {
					return []byte("APT::Periodic::Enable \"0\";"), nil
				}
				return []byte("APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";"), nil
			}}
			owner := "unattended-upgrades"
			if mode == "unavailable" {
				owner = "operator"
			}
			e := n.observeUpdateOwner(context.Background(), owner)
			if (e == nil) != (mode == "active-unattended") {
				t.Fatal(e)
			}
		})
	}
}

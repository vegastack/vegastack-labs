//go:build linux || darwin

package debianbaseline

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"os"
	"path"
	"strings"
	"time"
)

// Root preparation pins the exact source/keyring bytes and finite cached signed
// release selectors. This is OS configuration, never an approval/proof record.
type aptPreparedSources struct {
	Owner       string              `json:"owner"`
	Sources     []aptPreparedSource `json:"sources"`
	SoakSeconds int64               `json:"soakSeconds"`
}
type aptPreparedSource struct {
	SourceFile          string `json:"sourceFile"`
	ReleaseFile         string `json:"releaseFile"`
	KeyringFile         string `json:"keyringFile"`
	Fingerprint         string `json:"fingerprint"`
	Kind                string `json:"kind"`
	PackagesFile        string `json:"packagesFile"`
	PackagesReleasePath string `json:"packagesReleasePath"`
}

func (n *nativeRuntime) readAPT(ctx context.Context) ([]byte, error) {
	raw, e := protectedRead(n.root, "etc/vsk-labs/baseline/apt-sources.json", 65536)
	if e != nil {
		return nil, e
	}
	var cfg aptPreparedSources
	if decode(raw, &cfg) != nil || len(cfg.Sources) == 0 || len(cfg.Sources) > 8 || cfg.SoakSeconds < 604800 {
		return nil, errBaseline
	}
	declared := map[string]bool{}
	for _, s := range cfg.Sources {
		declared[s.SourceFile] = true
	}
	entries, e := os.ReadDir(path.Join(n.root, "etc/apt/sources.list.d"))
	if e != nil {
		return nil, e
	}
	for _, entry := range entries {
		if (strings.HasSuffix(entry.Name(), ".sources") || strings.HasSuffix(entry.Name(), ".list")) && !declared[entry.Name()] {
			return nil, errBaseline
		}
	}
	if legacy, e := protectedRead(n.root, "etc/apt/sources.list", 65536); e == nil {
		for _, line := range strings.Split(string(legacy), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				return nil, errBaseline
			}
		}
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	hashes := map[string]string{}
	profileRaw, e := protectedRead(n.root, "etc/vsk-labs/debian-profile.json", 65536)
	if e != nil {
		return nil, e
	}
	var profile generated.DebianProfileLock
	if json.Unmarshal(profileRaw, &profile) != nil {
		return nil, errBaseline
	}
	needed := map[string]string{}
	for _, p := range profile.Packages {
		needed[p.Name] = p.Version
	}
	found := map[string]bool{}
	securitySeen := false
	soak := int64(1 << 62)

	now := n.now()
	obs := updateObservation{Owner: cfg.Owner, SignatureVerified: true, SoakSeconds: 0}
	for _, s := range cfg.Sources {
		if !safeName.MatchString(s.SourceFile) || !safeName.MatchString(s.ReleaseFile) || !safeName.MatchString(s.KeyringFile) || len(s.Fingerprint) != 40 {
			return nil, errBaseline
		}
		source, e := protectedRead(n.root, "etc/apt/sources.list.d/"+s.SourceFile, 65536)
		if e != nil {
			return nil, e
		}
		if !strings.Contains(string(source), "Signed-By: /usr/share/keyrings/"+s.KeyringFile) || strings.Contains(strings.ToLower(string(source)), "trusted: yes") {
			return nil, errBaseline
		}
		key, e := protectedRead(n.root, "usr/share/keyrings/"+s.KeyringFile, 4<<20)
		if e != nil {
			return nil, e
		}
		hashes[s.SourceFile] = digestBytes(source)
		hashes[s.KeyringFile] = digestBytes(key)
		release, e := protectedRead(n.root, "var/lib/apt/lists/"+s.ReleaseFile, 4<<20)
		if e != nil {
			return nil, e
		}
		verified, e := n.run(ctx, "/usr/bin/gpgv", []string{"--status-fd=1", "--keyring", path.Join(n.root, "usr/share/keyrings", s.KeyringFile), path.Join(n.root, "var/lib/apt/lists", s.ReleaseFile)}, nil)
		if e != nil || !strings.Contains(string(verified), "[GNUPG:] VALIDSIG "+s.Fingerprint+" ") {
			return nil, errBaseline
		}
		releaseNow, readErr := protectedRead(n.root, "var/lib/apt/lists/"+s.ReleaseFile, 4<<20)
		if readErr != nil || digestBytes(releaseNow) != digestBytes(release) {
			return nil, errBaseline
		}
		keyNow, readErr := protectedRead(n.root, "usr/share/keyrings/"+s.KeyringFile, 4<<20)
		if readErr != nil || digestBytes(keyNow) != digestBytes(key) {
			return nil, errBaseline
		}
		sourceNow, readErr := protectedRead(n.root, "etc/apt/sources.list.d/"+s.SourceFile, 65536)
		if readErr != nil || digestBytes(sourceNow) != digestBytes(source) {
			return nil, errBaseline
		}
		payload, e := signedReleasePayload(release)
		if e != nil {
			return nil, e
		}
		dates := map[string]time.Time{}
		for _, line := range strings.Split(string(payload), "\n") {
			k, v, ok := strings.Cut(line, ": ")
			if ok && (k == "Date" || k == "Valid-Until") {
				d, e := time.Parse(time.RFC1123Z, v)
				if e != nil {
					d, e = time.Parse(time.RFC1123, v)
				}
				if e != nil {
					return nil, errBaseline
				}
				dates[k] = d
			}
		}

		if dates["Date"].IsZero() || dates["Date"].After(now) || (!dates["Valid-Until"].IsZero() && !now.Before(dates["Valid-Until"])) {
			return nil, errBaseline
		}
		if s.Kind == "security" {
			if dates["Valid-Until"].IsZero() {
				return nil, errBaseline
			}
			securitySeen = true
			if now.Sub(dates["Date"]) > 24*time.Hour {
				return nil, errBaseline
			}
			if obs.SignedAt.IsZero() || dates["Date"].Before(obs.SignedAt) {
				obs.SignedAt = dates["Date"]
			}
		} else if s.Kind == "snapshot" {
			hashes[s.ReleaseFile] = digestBytes(release)
			age := int64(now.Sub(dates["Date"]).Seconds())
			if age < 604800 {
				return nil, errBaseline
			}
			if age < soak {
				soak = age
			}
			if !safeName.MatchString(s.PackagesFile) || path.Clean(s.PackagesReleasePath) != s.PackagesReleasePath || strings.HasPrefix(s.PackagesReleasePath, "/") || strings.Contains(s.PackagesReleasePath, "..") {
				return nil, errBaseline
			}
			packages, e := protectedRead(n.root, "var/lib/apt/lists/"+s.PackagesFile, 128<<20)
			if e != nil {
				return nil, e
			}
			expected := ""
			inSHA := false
			for _, line := range strings.Split(string(payload), "\n") {
				if line == "SHA256:" {
					inSHA = true
					continue
				}
				if inSHA && !strings.HasPrefix(line, " ") {
					inSHA = false
				}
				f := strings.Fields(line)
				if inSHA && len(f) == 3 && f[2] == s.PackagesReleasePath {
					expected = "sha256:" + f[0]
				}
			}
			if expected == "" || digestBytes(packages) != expected {
				return nil, errBaseline
			}
			for _, block := range strings.Split(string(packages), "\n\n") {
				fields := map[string]string{}
				for _, line := range strings.Split(block, "\n") {
					k, v, ok := strings.Cut(line, ": ")
					if ok && (k == "Package" || k == "Version") {
						fields[k] = v
					}
				}
				if want, ok := needed[fields["Package"]]; ok && want == fields["Version"] {
					found[fields["Package"]] = true
				}
			}
		} else {
			return nil, errBaseline
		}
		if !dates["Valid-Until"].IsZero() && (obs.ValidUntil.IsZero() || dates["Valid-Until"].Before(obs.ValidUntil)) {
			obs.ValidUntil = dates["Valid-Until"]
		}

	}
	if !securitySeen || len(found) != len(needed) || soak == int64(1<<62) {
		return nil, errBaseline
	}
	obs.SoakSeconds = soak
	obs.SourceDigest = hostaction.Digest(hashes)
	if _, e = os.Stat(path.Join(n.root, "run/reboot-required")); e == nil {
		obs.PendingReboot = true
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	// Conflicting automated update owners are observed, never disabled here.
	for _, unit := range []string{"apt-daily.timer", "apt-daily-upgrade.timer"} {
		b, e := n.run(ctx, "/usr/bin/systemctl", []string{"is-active", unit}, nil)
		active := e == nil && strings.TrimSpace(string(b)) == "active"
		if cfg.Owner == "operator" && active {
			return nil, errBaseline
		}
	}
	return json.Marshal(obs)
}

func signedReleasePayload(raw []byte) ([]byte, error) {
	s := strings.ReplaceAll(string(raw), "\r\n", "\n")
	prefix := "-----BEGIN PGP SIGNED MESSAGE-----\n"
	if !strings.HasPrefix(s, prefix) {
		return nil, errBaseline
	}
	headers, body, ok := strings.Cut(strings.TrimPrefix(s, prefix), "\n\n")
	if !ok {
		return nil, errBaseline
	}
	for _, h := range strings.Split(headers, "\n") {
		if !strings.HasPrefix(h, "Hash: ") {
			return nil, errBaseline
		}
	}
	content, signature, ok := strings.Cut(body, "\n-----BEGIN PGP SIGNATURE-----\n")
	if !ok {
		return nil, errBaseline
	}
	_, tail, ok := strings.Cut(signature, "-----END PGP SIGNATURE-----")
	if !ok || strings.TrimSpace(tail) != "" {
		return nil, errBaseline
	}
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, "- ") {
			lines[i] = strings.TrimPrefix(line, "- ")
		} else if strings.HasPrefix(line, "-") {
			return nil, errBaseline
		}
	}
	return []byte(strings.Join(lines, "\n")), nil
}

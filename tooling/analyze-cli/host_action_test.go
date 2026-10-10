package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHostActionSourceSealRejectsChangedAddedOrImportedAuthority(t *testing.T) {
	const module = "github.com/vegastack/vegastack-labs"
	// Exercise current source closures. Historical #223/#225 seals remain
	// immutable; files evolved by #226 use their additive current wave.
	currentSeals := map[string]hostActionSourceSeal{}
	for key, seal := range hostActionSourceSeals {
		relative := strings.SplitN(key, "|", 2)[0]
		if relative != "cmd/vsk-labs" && relative != "internal/hostaction" {
			currentSeals[key] = seal
		}
	}
	for key, seal := range debianBaselineSourceSeals {
		currentSeals[key] = seal
	}
	// #230 replaces only the current composition/renderer closures; retain
	// the older seals as immutable historical decisions.
	for key := range currentSeals {
		relative := strings.SplitN(key, "|", 2)[0]
		if relative == "cmd/vsk-labs" || relative == "internal/adapter/hostaction" {
			delete(currentSeals, key)
		}
	}
	for key, seal := range linuxRoleSourceSeals {
		relative := strings.SplitN(key, "|", 2)[0]
		if relative == "cmd/vsk-labs" || relative == "internal/adapter/hostaction" {
			currentSeals[key] = seal
		}
	}
	// #228 current bytes use their additive exact seals; historical maps stay
	// immutable decisions rather than fixtures of today's bytes.
	for key := range currentSeals {
		relative := strings.SplitN(key, "|", 2)[0]
		for current := range phase228SourceSeals {
			if strings.HasPrefix(current, relative+"|") {
				delete(currentSeals, key)
				break
			}
		}
	}
	for key, seal := range phase228SourceSeals {
		currentSeals[key] = seal
	}
	for key, seal := range currentSeals {
		t.Run(key, func(t *testing.T) {
			parts := strings.SplitN(key, "|", 2)
			names := strings.Split(parts[1], ",")
			dir := t.TempDir()
			for _, name := range names {
				raw, err := os.ReadFile(filepath.Join("..", "..", parts[0], name))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			candidate := checkedSourcePackage{sourcePackage: sourcePackage{listed: listedPackage{ImportPath: module + "/" + parts[0], Dir: dir, GoFiles: names, Imports: append([]string(nil), seal.imports...)}}}
			if !(reviewedHostActionPackage(candidate, module, parts[0]) || reviewedPhase228Package(candidate, module, parts[0])) {
				t.Fatal("exact reviewed source refused")
			}
			original, err := os.ReadFile(filepath.Join(dir, names[0]))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, names[0]), append(original, []byte("\n// unreviewed change\n")...), 0600); err != nil {
				t.Fatal(err)
			}
			if reviewedHostActionPackage(candidate, module, parts[0]) || reviewedPhase228Package(candidate, module, parts[0]) {
				t.Fatal("changed source inherited authority")
			}
			if err := os.WriteFile(filepath.Join(dir, names[0]), original, 0600); err != nil {
				t.Fatal(err)
			}
			candidate.listed.Imports = append(candidate.listed.Imports, "unsafe.example/privilege")
			if reviewedHostActionPackage(candidate, module, parts[0]) || reviewedPhase228Package(candidate, module, parts[0]) {
				t.Fatal("new import inherited authority")
			}
			candidate.listed.Imports = seal.imports
			candidate.listed.GoFiles = append(append([]string(nil), names...), "extra.go")
			if reviewedHostActionPackage(candidate, module, parts[0]) || reviewedPhase228Package(candidate, module, parts[0]) {
				t.Fatal("extra source inherited authority")
			}
		})
	}
}
func TestHostActionSignerAllowanceDoesNotAuthorizeOtherServerSigners(t *testing.T) {
	const module = "github.com/vegastack/vegastack-labs"
	dir := t.TempDir()
	raw, err := os.ReadFile(filepath.Join("..", "..", "internal", "server", "host_action_signer_linux.go"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "host_action_signer_linux.go"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	canary, err := os.ReadFile(filepath.Join("..", "..", "internal", "server", "recovery_canary_system.go"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "recovery_canary_system.go"), canary, 0600); err != nil {
		t.Fatal(err)
	}
	c := checkedSourcePackage{sourcePackage: sourcePackage{listed: listedPackage{ImportPath: module + "/internal/server", Dir: dir, GoFiles: []string{"host_action_signer_linux.go", "recovery_canary_system.go"}}}}
	if !reviewedHostActionServerSigner(c, module+"/internal/server") {
		t.Fatal("exact action signer refused")
	}
	if err := os.WriteFile(filepath.Join(dir, "other.go"), []byte("package server\nimport e \"crypto/ed25519\"\nvar injected=e.Sign\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c.listed.GoFiles = append(c.listed.GoFiles, "other.go")
	if reviewedHostActionServerSigner(c, module+"/internal/server") {
		t.Fatal("another signer inherited action-key permission")
	}
}

func TestHostActionSignerPreservesRecoveryCanarySeal(t *testing.T) {
	const module = "github.com/vegastack/vegastack-labs"
	dir := t.TempDir()
	raw, err := os.ReadFile(filepath.Join("..", "..", "internal", "server", "host_action_signer_linux.go"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "host_action_signer_linux.go"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "recovery_canary_system.go"), []byte("package server\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c := checkedSourcePackage{sourcePackage: sourcePackage{listed: listedPackage{ImportPath: module + "/internal/server", Dir: dir, GoFiles: []string{"host_action_signer_linux.go", "recovery_canary_system.go"}}}}
	if reviewedHostActionServerSigner(c, module+"/internal/server") {
		t.Fatal("action signer allowance bypassed existing recovery source seal")
	}
}

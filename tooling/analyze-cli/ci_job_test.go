package main

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestCIJobCurrentSourceSealsRejectDrift(t *testing.T) {
	const module = "github.com/vegastack/vegastack-labs"
	if len(ciJobSourceSeals) == 0 {
		t.Fatal("missing CI job source seals")
	}
	// Current-file fixtures select the current #318 runtime variants; old seals
	// continue to authenticate their historical bytes, not today's source.
	current := maps.Clone(ciJobSourceSeals)
	for key := range current {
		if strings.HasPrefix(key, "internal/cijobrunner|") || strings.HasPrefix(key, "internal/serverconfig|") {
			delete(current, key)
		}
	}
	maps.Copy(current, ciNetworkSourceSeals)
	for key := range current {
		relative := strings.SplitN(key, "|", 2)[0]
		for candidate := range ciDeliverySourceSeals {
			if strings.HasPrefix(candidate, relative+"|") {
				delete(current, key)
				break
			}
		}
	}
	maps.Copy(current, ciDeliverySourceSeals)
	// Current #322 fixtures use only their package's additive pilot variants.
	for key := range current {
		relative := strings.SplitN(key, "|", 2)[0]
		for candidate := range ingressPilotSourceSeals {
			if strings.HasPrefix(candidate, relative+"|") {
				delete(current, key)
				break
			}
		}
	}
	for key, seal := range ingressPilotSourceSeals {
		current[key] = seal
	}

	for key, seal := range current {
		t.Run(key, func(t *testing.T) {
			parts := strings.SplitN(key, "|", 2)
			relative, names := parts[0], strings.Split(parts[1], ",")
			dir := t.TempDir()
			for _, name := range names {
				raw, err := os.ReadFile(filepath.Join("..", "..", relative, name))
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			c := checkedSourcePackage{sourcePackage: sourcePackage{listed: listedPackage{ImportPath: module + "/" + relative, Dir: dir, GoFiles: slices.Clone(names), Imports: slices.Clone(seal.imports)}}}
			if !approvedNetworkConnectPackage(c, module, relative) {
				t.Fatal("exact CI job source variant denied")
			}
			first := filepath.Join(dir, names[0])
			raw, err := os.ReadFile(first)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(first, append(slices.Clone(raw), []byte("\n// changed source\n")...), 0600); err != nil {
				t.Fatal(err)
			}
			if approvedNetworkConnectPackage(c, module, relative) {
				t.Fatal("changed CI job source inherited authority")
			}
			if err = os.WriteFile(first, raw, 0600); err != nil {
				t.Fatal(err)
			}
			c.listed.GoFiles = slices.Clone(names)
			c.listed.GoFiles[0] = "renamed.go"
			if err = os.WriteFile(filepath.Join(dir, "renamed.go"), raw, 0600); err != nil {
				t.Fatal(err)
			}
			if approvedNetworkConnectPackage(c, module, relative) {
				t.Fatal("renamed source inherited authority")
			}
			c.listed.GoFiles = slices.Clone(names)
			originalPath := c.listed.ImportPath
			c.listed.ImportPath = module + "/internal/sibling"
			if approvedNetworkConnectPackage(c, module, relative) {
				t.Fatal("renamed package inherited authority")
			}
			c.listed.ImportPath = originalPath
			c.listed.GoFiles = append(c.listed.GoFiles, "extra.go")
			if err = os.WriteFile(filepath.Join(dir, "extra.go"), []byte("package extra\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if approvedNetworkConnectPackage(c, module, relative) {
				t.Fatal("sibling source inherited authority")
			}
			c.listed.GoFiles = slices.Clone(names)
			c.listed.Imports = append(c.listed.Imports, "net/rpc")
			if approvedNetworkConnectPackage(c, module, relative) {
				t.Fatal("new import inherited authority")
			}
		})
	}
}

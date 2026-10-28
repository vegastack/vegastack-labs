package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestNetworkConnectSourceSealsRejectDrift(t *testing.T) {
	const module = "github.com/vegastack/vegastack-labs"
	checked := 0
	current := make(map[string]hostActionSourceSeal)
	for key, seal := range networkConnectSourceSeals {
		if strings.HasPrefix(key, "internal/networkconnect|") {
			current[key] = seal
		}
	}
	for key, seal := range phase8FinishSourceSeals {
		current[key] = seal
	}
	// #304 current fixtures use the new exact client/profile/pure-policy variants.
	// Historical wave maps continue to describe their original bytes.
	for key := range current {
		relative := strings.SplitN(key, "|", 2)[0]
		for currentKey := range ciEnrollmentSourceSeals {
			if strings.HasPrefix(currentKey, relative+"|") {
				delete(current, key)
				break
			}
		}
	}
	for key, seal := range ciEnrollmentSourceSeals {
		current[key] = seal
	}

	// #313 current bytes supersede only their package's older fixture variants;
	// immutable historical source maps are left untouched.
	for key := range current {
		relative := strings.SplitN(key, "|", 2)[0]
		for currentKey := range currentCIJobFixtureSeals() {
			if strings.HasPrefix(currentKey, relative+"|") {
				delete(current, key)
				break
			}
		}
	}
	for key, seal := range currentCIJobFixtureSeals() {
		current[key] = seal
	}

	for key, seal := range current {
		relative, joined, _ := strings.Cut(key, "|")
		if !isCurrentCIJobFixturePackage(relative) && relative != "internal/ci" && relative != "internal/localapi" && relative != "internal/networkconnect" && relative != "internal/serverconfig" && relative != "internal/servicecatalog" && relative != "internal/hostinglifecycle" && relative != "internal/servicerecovery" && relative != "cmd/vsk-labs" && relative != "internal/hostingplatform" && relative != "internal/adapter/harbor" && relative != "internal/ingressconnector" {
			t.Fatalf("unexpected source seal %q", relative)
		}
		names := strings.Split(joined, ",")
		dir := t.TempDir()
		for _, name := range names {
			b, e := os.ReadFile(filepath.Join("..", "..", relative, name))
			if e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(filepath.Join(dir, name), b, 0600); e != nil {
				t.Fatal(e)
			}
		}
		c := checkedSourcePackage{}
		c.listed.Dir = dir
		c.listed.ImportPath = module + "/" + relative
		c.listed.GoFiles = names
		c.listed.Imports = slices.Clone(seal.imports)
		if relative == "internal/servicecatalog" && !approvedServiceCatalogPackage(c, module, relative) {
			t.Fatal("exact service validation source rejected")
		}
		if !approvedNetworkConnectPackage(c, module, relative) {
			t.Fatal("current finite source closure rejected")
		}
		c.listed.Imports = append(c.listed.Imports, "net/rpc")
		if approvedNetworkConnectPackage(c, module, relative) {
			t.Fatal("widened imports accepted")
		}
		c.listed.Imports = slices.Clone(seal.imports)
		c.listed.GoFiles = append(slices.Clone(names), "unapproved.go")
		if approvedNetworkConnectPackage(c, module, relative) {
			t.Fatal("added production source accepted")
		}
		c.listed.GoFiles = names
		p := filepath.Join(dir, names[0])
		f, e := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0600)
		if e != nil {
			t.Fatal(e)
		}
		_, _ = f.WriteString("\n// unreviewed source mutation\n")
		_ = f.Close()
		if approvedNetworkConnectPackage(c, module, relative) {
			t.Fatal("changed source accepted")
		}
		checked++
	}
	if checked != 24+1+1+2 {
		t.Fatal("all 24 existing platform/domain variants plus exact pilot/maintenance validators and connector runtime variants must be sealed")
	}
}

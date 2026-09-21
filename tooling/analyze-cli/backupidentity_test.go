package main

import "testing"

func TestLocalClientClosureAllowsOnlyPureBackupIdentityRegistry(t *testing.T) {
	const module = "example.test"
	base := map[string]bool{module + "/internal/localapi": true, module + "/internal/serverconfig": true}
	registry := module + "/internal/backupidentity"
	base[registry] = true
	if !reviewedLocalClientDependencies(base, module, module+"/internal/localapi", module+"/internal/localtransport", module+"/internal/sshtransport") {
		t.Fatal("pure registered identity dependency was rejected")
	}
	base[module+"/internal/unreviewed"] = true
	if reviewedLocalClientDependencies(base, module, module+"/internal/localapi", module+"/internal/localtransport", module+"/internal/sshtransport") {
		t.Fatal("unreviewed local client dependency was admitted")
	}
	delete(base, module+"/internal/unreviewed")
	for _, imports := range [][]string{{}, {"net/http"}, {module + "/internal/store"}} {
		candidate := checkedSourcePackage{listed: listedPackage{ImportPath: registry, Imports: imports}}
		allowed := reviewedLocalClientPackage(candidate, module, module+"/internal/localapi", module+"/internal/localtransport", module+"/internal/sshtransport")
		if allowed != (len(imports) == 0) {
			t.Fatalf("registry imports %v allowed=%v", imports, allowed)
		}
	}
}

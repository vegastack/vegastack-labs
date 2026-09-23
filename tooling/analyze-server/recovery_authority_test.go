package main

import (
	"strings"
	"testing"
)

func TestRecoveryAuthorityClosureRejectsPartialLateAndDirectRestore(t *testing.T) {
	valid := `
var productionDatabasePath = "/var/lib/vsk-labs/control.db"
func run() {
 manager := CandidateManager{DatabasePath: productionDatabasePath}
 manager.PromoteAtStartup()
 authority := operations.openStore(productionDatabasePath)
 _ = AuthorityAdmission{}
 _ = CanaryVerifier{}
 RegisterRestoreOperations(authority)
}`
	if invalidRecoveryAuthorityClosure(valid) {
		t.Fatal("complete single-authority closure rejected")
	}
	for name, source := range map[string]string{
		"partial":        strings.Replace(valid, "_ = CanaryVerifier{}", "", 1),
		"empty canary":   strings.Replace(valid, "_ = CanaryVerifier{}", "Canary: recovery.CanaryVerifier{}", 1),
		"late promotion": strings.Replace(valid, "manager.PromoteAtStartup()\n authority := operations.openStore", "authority := operations.openStore\n manager.PromoteAtStartup()", 1),
		"live overwrite": valid + `\nfunc overwrite(){ RestoreSnapshot(ctx, productionDatabasePath) }`,
		"second process": valid + `\nfunc daemon(){ exec.Command("recovery-daemon") }`,
	} {
		t.Run(name, func(t *testing.T) {
			if !invalidRecoveryAuthorityClosure(source) {
				t.Fatal("unsafe recovery closure accepted")
			}
		})
	}
}

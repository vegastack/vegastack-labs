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
 _ = StoreRecoveryCanary{}
 _ = CanaryVerifier{}
 RegisterRestoreOperations()
}
func (operations *Operations) openAuthorityWithPromotion() {
 authority, err := operations.openStore(productionDatabasePath)
 authority.Close()
 manager.PromoteAtStartup()
 return operations.openStore(ctx, configFor(operations.databasePath))
}`
	if invalidRecoveryAuthorityClosure(valid) {
		t.Fatal("complete single-authority closure rejected")
	}
	for name, source := range map[string]string{
		"partial":          strings.Replace(valid, "_ = CanaryVerifier{}", "", 1),
		"empty canary":     strings.Replace(valid, "_ = CanaryVerifier{}", "Canary: recovery.CanaryVerifier{}", 1),
		"unavailable port": valid + "\nvar unavailable = UnavailableCanaryBackup{}",
		"late promotion":   strings.Replace(valid, "manager.PromoteAtStartup()\n return operations.openStore", "return operations.openStore\n manager.PromoteAtStartup()", 1),
		"live former":      strings.Replace(valid, "authority.Close()", "", 1),
		"live overwrite":   valid + `\nfunc overwrite(){ RestoreSnapshot(ctx, productionDatabasePath) }`,
		"second process":   valid + `\nfunc daemon(){ exec.Command("recovery-daemon") }`,
	} {
		t.Run(name, func(t *testing.T) {
			if !invalidRecoveryAuthorityClosure(source) {
				t.Fatal("unsafe recovery closure accepted")
			}
		})
	}
}

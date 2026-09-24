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
 server.WithRecoveryCanaryPortFactory()
 registerProductionRecoveryCredentialResolver()
 authority.WithRecoveryCanaryMutation()
 authority.RecordRecoveryCanaryCheckpoint()
 adapter.CreateAndVerifyRecoveryCanaryBackup()
 borrower.BorrowRecoveryCanaryCredential()
 RegisterRestoreOperations()
}
func (operations *Operations) openAuthorityWithPromotion() {
 authority, err := operations.openStore(productionDatabasePath)
 authority.Close()
 manager.PromoteAtStartup()
 return operations.openStore(ctx, configFor(operations.databasePath))
}`
	recovery := `var productionDenialFactories = map[string]qualifiedFactory{"https-direct-denial-v1": {}}
func (canary StoreRecoveryCanary) VerifyOldEpochDenied() { AttemptOldEpochMutation() }
func (store *Store) WithRecoveryCanaryMutation() {}
func (store *Store) RecordRecoveryCanaryCheckpoint() {}
func (repository *BackupRepository) PrepareRecoveryCanaryBackupPolicy() {}`
	if invalidRecoveryAuthorityClosure(valid, recovery) {
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
			if !invalidRecoveryAuthorityClosure(source, recovery) {
				t.Fatal("unsafe recovery closure accepted")
			}
		})
	}
	for name, unsafeRecovery := range map[string]string{
		"empty production denial registry": `var productionDenialFactories = map[string]qualifiedFactory{}`,
		"observation only old epoch": recovery + `
func weak(){ if bundle.Binding.PriorRecoveryEpoch+1 != current.RecoveryEpoch {} }`,
	} {
		t.Run(name, func(t *testing.T) {
			if !invalidRecoveryAuthorityClosure(valid, unsafeRecovery) {
				t.Fatal("unsafe recovery source accepted")
			}
		})
	}
}

package metadata

func nativePreparationSchemas() []SchemaDefinition {
	request := []FieldDefinition{discoveryRef("binding", "Binding", "vegastack-labs.dev/native-step-request"), phase5Enum("kind", "Kind", "target", "discover", "adopt", "access", "action", "plan", "approval", "approval-status", "host", "gate", "replacement", "replacement-state", "credential-lifecycle", "backup-policy", "backup-run", "backup-verify", "restore-plan", "restore-run", "restore-verify", "fixture-approval", "producer-lookup"), nativeSetupOptionalText("declarationId", "DeclarationID", 128), nativeOptionalInteger("declarationRevision", "DeclarationRevision"), nativeSetupOptionalText("identifier", "Identifier", 128), nativeSetupOptionalText("gateId", "GateID", 128)}
	for _, f := range []struct{ j, g, s string }{{"producerLookup", "ProducerLookup", "native-producer-lookup-request"}, {"fixtureApproval", "FixtureApproval", "native-slack-fixture-approval"}, {"target", "Target", "host-discovery-target-draft-request"}, {"discovery", "Discovery", "host-discovery-request"}, {"adoption", "Adoption", "host-adoption-request"}, {"access", "Access", "host-access-draft-request"}, {"action", "Action", "host-action-request"}, {"replacement", "Replacement", "host-replacement-request"}, {"credentialLifecycle", "CredentialLifecycle", "credential-lifecycle-request"}, {"approval", "Approval", "plan-reference-request"}, {"backupPolicy", "BackupPolicy", "backup-policy-draft-request"}, {"backupRun", "BackupRun", "backup-run-request"}, {"backupVerify", "BackupVerify", "backup-verify-request"}, {"restorePlan", "RestorePlan", "restore-request"}, {"restoreRun", "RestoreRun", "restore-run-request"}, {"restoreVerify", "RestoreVerify", "restore-verify-request"}} {
		request = append(request, nativeOptionalRef(f.j, f.g, f.s))
	}
	result := []FieldDefinition{discoveryRef("result", "Result", "vegastack-labs.dev/run-result"), phase5Nonnegative("exitCode", "ExitCode")}
	for _, f := range []struct{ j, g, s string }{{"producerReference", "ProducerReference", "native-producer-reference"}, {"target", "Target", "host-discovery-target-draft-submission"}, {"discovery", "Discovery", "host-discovery-submission"}, {"adoption", "Adoption", "host-adoption-submission"}, {"action", "Action", "host-action-submission"}, {"replacement", "Replacement", "host-replacement-submission"}, {"credentialLifecycle", "CredentialLifecycle", "credential-lifecycle-submission"}, {"plan", "Plan", "plan"}, {"approval", "Approval", "approval-status"}, {"host", "Host", "managed-host"}, {"gate", "Gate", "gate-view"}, {"replacementState", "ReplacementState", "host-replacement-state"}, {"backupPolicy", "BackupPolicy", "backup-policy-draft-submission"}, {"backupJob", "BackupJob", "backup-job"}, {"restoreBinding", "RestoreBinding", "restore-binding"}, {"restoreVerification", "RestoreVerification", "restore-verification"}} {
		result = append(result, nativeOptionalRef(f.j, f.g, f.s))
	}
	return []SchemaDefinition{phase5Schema("vegastack-labs.dev/native-preparation-request", request...), phase5Schema("vegastack-labs.dev/native-preparation-result", result...)}
}
func nativeOptionalInteger(name, goName string) FieldDefinition {
	f := phase5Nonnegative(name, goName)
	f.Required = false
	f.OmitEmpty = true
	return f
}

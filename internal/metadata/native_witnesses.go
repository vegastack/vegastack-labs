package metadata

func nativeOptionalRef(name, goName, schema string) FieldDefinition {
	return FieldDefinition{JSONName: name, GoName: goName, Kind: ValueObject, Ref: "vegastack-labs.dev/" + schema, Nullable: true, OmitEmpty: true}
}
func nativeWitnessSchemas() []SchemaDefinition {
	rollback := []FieldDefinition{phase5Digest("recordDigest", "RecordDigest"), phase5ID("runId", "RunID"), phase5ID("hostId", "HostID"), phase5Digest("hostIdentityDigest", "HostIdentityDigest"), phase5ID("planId", "PlanID"), phase5Digest("inputDigest", "InputDigest"), phase5Digest("authorizationDigest", "AuthorizationDigest"), phase5Digest("bundleDigest", "BundleDigest"), phase5Enum("state", "State", "armed", "confirmed", "restored", "uncertain", "services-pending"), nativeWitnessTimestamp("armedAt", "ArmedAt"), nativeWitnessTimestamp("deadline", "Deadline"), nativeWitnessTimestamp("observedAt", "ObservedAt"), phase5ID("armedBootId", "ArmedBootID"), phase5ID("currentBootId", "CurrentBootID"), phase5Digest("beforeOwnedDigest", "BeforeOwnedDigest"), phase5Digest("appliedOwnedDigest", "AppliedOwnedDigest"), phase5Digest("currentOwnedDigest", "CurrentOwnedDigest"), phase5Nonnegative("fileCount", "FileCount"), phase5Nonnegative("firewallCount", "FirewallCount")}
	optional := phase5ID("reconciledBootId", "ReconciledBootID")
	optional.Required = false
	optional.OmitEmpty = true
	rollback = append(rollback, optional)
	return []SchemaDefinition{
		phase5Schema("vegastack-labs.dev/native-volume-case-witness", nativeVolumeScenario(), phase5Digest("inputDigest", "InputDigest"), phase5Digest("bindingDigest", "BindingDigest"), phase5Digest("headerBeforeDigest", "HeaderBeforeDigest"), phase5Digest("headerAfterDigest", "HeaderAfterDigest"), phase5Digest("originalPolicyDigest", "OriginalPolicyDigest"), phase5Digest("originalPolicyAfterDigest", "OriginalPolicyAfterDigest"), phase5Digest("testedCopyBeforeDigest", "TestedCopyBeforeDigest"), phase5Digest("testedCopyAfterDigest", "TestedCopyAfterDigest"), phase5Nonnegative("testedKeySlot", "TestedKeySlot"), phase5Enum("observedOutcome", "ObservedOutcome", "accepted", "refused"), nativeWitnessTimestamp("observedAt", "ObservedAt"), nativeOptionalRef("baselineInput", "BaselineInput", "debian-baseline-input"), nativeOptionalRef("recoveryInput", "RecoveryInput", "volume-recovery-input"), nativeOptionalRef("priorRecoveryInput", "PriorRecoveryInput", "volume-recovery-input")),

		phase5Schema("vegastack-labs.dev/native-action-negative-observation", phase5Enum("variant", "Variant", "malformed-envelope", "wrong-host", "wrong-plan", "wrong-epoch", "invalid-signature"), discoveryRef("denial", "Denial", "vegastack-labs.dev/host-action-denial")),
		phase5Schema("vegastack-labs.dev/native-action-protocol-witness", accessList("negativeAttempts", "NegativeAttempts", "vegastack-labs.dev/native-action-negative-observation", 5), discoveryRef("bundle", "Bundle", "vegastack-labs.dev/host-action-bundle"), phase5Enum("scenarioId", "ScenarioID", "action-replay", "action-concurrency"), nativeAttemptCount("concurrentAttempts", "ConcurrentAttempts", true), nativeAttemptCount("completedResults", "CompletedResults", false), accessList("concurrentDenials", "ConcurrentDenials", "vegastack-labs.dev/host-action-denial", 2), discoveryRef("replayDenial", "ReplayDenial", "vegastack-labs.dev/host-action-denial"), discoveryRef("replayAfterDenial", "ReplayAfterDenial", "vegastack-labs.dev/host-action-denial"), phase5Digest("resultDigest", "ResultDigest"), nativeWitnessTimestamp("observedAt", "ObservedAt")),
		phase5Schema("vegastack-labs.dev/native-action-receipt-witness", discoveryRef("bundle", "Bundle", "vegastack-labs.dev/host-action-bundle"), phase5Digest("executionDigest", "ExecutionDigest"), phase5Digest("bundleDigest", "BundleDigest"), phase5Digest("claimDigest", "ClaimDigest"), phase5Digest("resultDigest", "ResultDigest"), phase5Enum("status", "Status", "succeeded", "partial", "failed"), nativeWitnessTimestamp("observedAt", "ObservedAt")),

		phase5Schema("vegastack-labs.dev/native-control-setup-attempt", phase5Enum("kind", "Kind", "incomplete-refusal", "fresh", "populated-refusal", "writer-refusal", "restart", "crash-restart"), phase5Digest("beforeDigest", "BeforeDigest"), phase5Digest("afterDigest", "AfterDigest"), nativeSetupOptionalText("errorCode", "ErrorCode", 64), nativeSetupOptionalText("instanceId", "InstanceID", 128), phase5Nonnegative("pid", "PID"), nativeSetupOptionalText("startIdentity", "StartIdentity", 256), nativeWitnessTimestamp("observedAt", "ObservedAt")),
		phase5Schema("vegastack-labs.dev/native-control-setup-witness", discoveryRef("fixtureScope", "FixtureScope", "vegastack-labs.dev/native-slack-fixture-scope"), phase5Digest("scopeDigest", "ScopeDigest"), phase5Positive("peerPid", "PeerPID"), discoveryText("peerStartIdentity", "PeerStartIdentity", 256), phase5ID("setupId", "SetupID"), phase5Digest("setupRequestDigest", "SetupRequestDigest"), phase5Digest("setupReviewDigest", "SetupReviewDigest"), phase5Digest("approvalDigest", "ApprovalDigest"), phase5ID("instanceId", "InstanceID"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), phase5Positive("initialPid", "InitialPID"), discoveryText("initialStartIdentity", "InitialStartIdentity", 256), phase5Positive("finalPid", "FinalPID"), discoveryText("finalStartIdentity", "FinalStartIdentity", 256), nativeWitnessTimestamp("observedAt", "ObservedAt"), accessList("attempts", "Attempts", "vegastack-labs.dev/native-control-setup-attempt", 8)),

		phase5Schema("vegastack-labs.dev/native-rollback-witness", rollback...),
		phase5Schema("vegastack-labs.dev/native-fail2ban-input", discoveryRef("target", "Target", "vegastack-labs.dev/host-discovery-target"), discoveryRef("source", "Source", "vegastack-labs.dev/access-probe-source"), discoveryRef("destination", "Destination", "vegastack-labs.dev/access-probe-tuple")),
		phase5Schema("vegastack-labs.dev/native-fail2ban-state", phase5Nonnegative("failedTotal", "FailedTotal"), phase5Nonnegative("bannedTotal", "BannedTotal"), accessStrings("banned", "Banned", 32), phase5Positive("maxRetry", "MaxRetry"), phase5Positive("findTimeSeconds", "FindTimeSeconds"), phase5Positive("banTimeSeconds", "BanTimeSeconds"), nativeWitnessTimestamp("observedAt", "ObservedAt")),
		phase5Schema("vegastack-labs.dev/native-ssh-observation", phase5ID("sourceHostId", "SourceHostID"), phase5Digest("sourceIdentityDigest", "SourceIdentityDigest"), phase5ID("destinationHostId", "DestinationHostID"), phase5Digest("destinationIdentityDigest", "DestinationIdentityDigest"), discoveryText("destinationAddress", "DestinationAddress", 64), nativeWitnessPort(), discoveryText("user", "User", 64), baselineOptionalDigest("publicKeyDigest", "PublicKeyDigest"), phase5Digest("inputDigest", "InputDigest"), discoveryText("sourceAddress", "SourceAddress", 64), phase5Digest("namespaceDigest", "NamespaceDigest"), phase5Digest("routeDigest", "RouteDigest"), FieldDefinition{JSONName: "outcomes", GoName: "Outcomes", Kind: ValueArray, Required: true, ItemKind: ValueString, MaxItems: intPointer(5)}, accessBool("hostKeyVerified", "HostKeyVerified"), nativeWitnessTimestamp("observedAt", "ObservedAt")),
		phase5Schema("vegastack-labs.dev/native-fail2ban-witness", discoveryRef("before", "Before", "vegastack-labs.dev/native-fail2ban-state"), discoveryRef("banned", "Banned", "vegastack-labs.dev/native-fail2ban-state"), discoveryRef("after", "After", "vegastack-labs.dev/native-fail2ban-state"), discoveryRef("failures", "Failures", "vegastack-labs.dev/native-ssh-observation"), discoveryRef("adminBefore", "AdminBefore", "vegastack-labs.dev/native-ssh-observation"), discoveryRef("adminDuring", "AdminDuring", "vegastack-labs.dev/native-ssh-observation"), discoveryRef("adminAfter", "AdminAfter", "vegastack-labs.dev/native-ssh-observation"), phase5Nonnegative("elapsedNanoseconds", "ElapsedNanoseconds")),
		phase5Schema("vegastack-labs.dev/native-volume-seal-witness", phase5Digest("headerBeforeDigest", "HeaderBeforeDigest"), phase5Digest("headerAfterDigest", "HeaderAfterDigest"), phase5Digest("copyBeforeDigest", "CopyBeforeDigest"), phase5Digest("copyAfterDigest", "CopyAfterDigest"), phase5Nonnegative("seals", "Seals"), phase5Nonnegative("writeErrno", "WriteErrno"), phase5Nonnegative("resizeErrno", "ResizeErrno"), phase5Nonnegative("reopenWriteErrno", "ReopenWriteErrno"), nativeWitnessTimestamp("observedAt", "ObservedAt")),
		phase5Schema("vegastack-labs.dev/native-control-service-state", phase5ID("databaseInstanceId", "DatabaseInstanceID"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), phase5Positive("serviceUid", "ServiceUID"), phase5Positive("pid", "PID"), discoveryText("startIdentity", "StartIdentity", 256), phase5Digest("writerLockDigest", "WriterLockDigest"), phase5Digest("unitDigest", "UnitDigest"), phase5Digest("configDigest", "ConfigDigest"), phase5Digest("executableDigest", "ExecutableDigest"), phase5Digest("socketIdentityDigest", "SocketIdentityDigest"), accessBool("serviceActive", "ServiceActive"), accessBool("healthy", "Healthy")),
		phase5Schema("vegastack-labs.dev/native-control-handoff-witness", discoveryRef("bundle", "Bundle", "vegastack-labs.dev/host-action-bundle"), discoveryRef("input", "Input", "vegastack-labs.dev/linux-role-input"), phase5Digest("receiptDigest", "ReceiptDigest"), discoveryRef("recordedState", "RecordedState", "vegastack-labs.dev/native-control-service-state"), discoveryRef("currentState", "CurrentState", "vegastack-labs.dev/native-control-service-state"), nativeWitnessTimestamp("observedAt", "ObservedAt")),
		phase5Schema("vegastack-labs.dev/native-witness-request", discoveryRef("binding", "Binding", "vegastack-labs.dev/native-step-request"), phase5Enum("kind", "Kind", "rollback", "fail2ban-state", "ssh-failures", "ssh-admin", "volume-seal", "control-handoff", "control-setup", "action-receipt", "volume-case"), baselineOptionalDigest("rollbackRecordDigest", "RollbackRecordDigest"), nativeOptionalRef("fail2banInput", "Fail2banInput", "native-fail2ban-input"), nativeOptionalRef("volumeInput", "VolumeInput", "volume-recovery-input"), nativeOptionalRef("actionBundle", "ActionBundle", "host-action-bundle"), nativeOptionalRef("baselineInput", "BaselineInput", "debian-baseline-input"), nativeOptionalRef("priorVolumeInput", "PriorVolumeInput", "volume-recovery-input")),
	}
}

func nativeWitnessTimestamp(name, goName string) FieldDefinition {
	f := phase5Timestamp(name, goName)
	f.Pattern = "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,9})?Z$"
	return f
}

func nativeWitnessPort() FieldDefinition {
	f := phase5Positive("destinationPort", "DestinationPort")
	f.Maximum = int64Pointer(65535)
	return f
}

func nativeSetupOptionalText(name, goName string, n int) FieldDefinition {
	f := discoveryText(name, goName, n)
	f.Required = false
	f.OmitEmpty = true
	return f
}

func nativeAttemptCount(name, goName string, positive bool) FieldDefinition {
	f := phase5Nonnegative(name, goName)
	if positive {
		f = phase5Positive(name, goName)
	}
	f.Maximum = int64Pointer(3)
	return f
}

func nativeVolumeScenario() FieldDefinition {
	return phase5Enum("scenarioId", "ScenarioID", "volume-effective-mapping", "volume-recovery-positive", "volume-wrong-key", "volume-wrong-header", "volume-wrong-slot", "volume-wrong-mapping", "volume-revoked-binding", "volume-unchanged-after-verification", "volume-inconsistent-redundant-header", "volume-status-no-original-repair")
}

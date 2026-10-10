package metadata

const qualificationScopeID = "vegastack-labs.dev/qualification-scope"

func qualificationSchemas() []SchemaDefinition {
	binding := []FieldDefinition{phase5Digest("scopeDigest", "ScopeDigest"), phase5ID("guestId", "GuestID"), qualificationScenario(), phase5Nonnegative("ordinal", "Ordinal"), phase5ID("controllerInstanceId", "ControllerInstanceID"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), phase5ID("planId", "PlanID"), phase5Digest("planDigest", "PlanDigest"), phase5ID("runId", "RunID"), phase5ID("stepId", "StepID"), phase5ID("leaseId", "LeaseID"), phase5Digest("nonce", "Nonce"), phase5Timestamp("deadline", "Deadline")}
	stepBinding := append([]FieldDefinition{}, binding...)
	for i := range stepBinding {
		if stepBinding[i].JSONName == "planId" || stepBinding[i].JSONName == "planDigest" || stepBinding[i].JSONName == "runId" || stepBinding[i].JSONName == "stepId" || stepBinding[i].JSONName == "leaseId" {
			stepBinding[i].Required = false
			stepBinding[i].OmitEmpty = true
		}
	}
	step := append(stepBinding, phase5Enum("operation", "Operation", "observe", "execute", "reboot-continuation", "collect-native", "witness", "cleanup-native", "prepare", "reboot-native", "select-controller"))
	return []SchemaDefinition{
		phase5Schema("vegastack-labs.dev/native-qualification-prerequisite", phase5Enum("stage", "Stage", "baseline", "role"), phase5ID("evidenceId", "EvidenceID"), phase5Digest("bundleDigest", "BundleDigest"), phase5Digest("artifactDigest", "ArtifactDigest")),
		phase5Schema("vegastack-labs.dev/native-qualification-producer", discoveryRef("reference", "Reference", "vegastack-labs.dev/native-producer-reference"), phase5Digest("hostIdentityDigest", "HostIdentityDigest"), phase5Digest("receiptDigest", "ReceiptDigest")),
		phase5Schema("vegastack-labs.dev/native-controller-identity", phase5ID("hostId", "HostID"), phase5Digest("hostIdentityDigest", "HostIdentityDigest"), FieldDefinition{JSONName: "hostMachineId", GoName: "HostMachineID", Kind: ValueString, Required: true, Pattern: "^[0-9a-f]{32}$"}, phase5ID("controllerInstanceId", "ControllerInstanceID"), phase5Digest("scopeDigest", "ScopeDigest"), phase5Digest("executableDigest", "ExecutableDigest")),
		phase5Schema("vegastack-labs.dev/native-qualification", nativeOptionalRef("controllerIdentity", "ControllerIdentity", "native-controller-identity"), FieldDefinition{JSONName: "prerequisites", GoName: "Prerequisites", Kind: ValueArray, ItemRef: "vegastack-labs.dev/native-qualification-prerequisite", MaxItems: intPointer(2), OmitEmpty: true}, phase5Enum("stage", "Stage", "baseline", "role", "recovery"), phase5Digest("scopeDigest", "ScopeDigest"), phase5ID("profileId", "ProfileID"), phase5Digest("profileLockDigest", "ProfileLockDigest"), FieldDefinition{JSONName: "sourceCommit", GoName: "SourceCommit", Kind: ValueString, Required: true, Pattern: "^[0-9a-f]{40}$"}, phase5Digest("sourceDigest", "SourceDigest"), phase5Digest("executableDigest", "ExecutableDigest"), phase5ID("controllerInstanceId", "ControllerInstanceID"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), phase5Timestamp("observedAt", "ObservedAt"), phase5Timestamp("expiresAt", "ExpiresAt"), phase5Digest("observerDigest", "ObserverDigest"), accessList("producers", "Producers", "vegastack-labs.dev/native-qualification-producer", 48)),
		phase5Schema("vegastack-labs.dev/native-collect-data", phase5Digest("bundleDigest", "BundleDigest"), FieldDefinition{JSONName: "scenarios", GoName: "Scenarios", Kind: ValueArray, Required: true, ItemRef: "vegastack-labs.dev/scenario-result", MinItems: intPointer(1), MaxItems: intPointer(27)}, discoveryRef("submission", "Submission", gateEvidenceSubmissionSchemaID), phase5Digest("requestDigest", "RequestDigest")),
		phase5Schema("vegastack-labs.dev/suitability-facts", phase5ID("targetId", "TargetID"), phase5Positive("targetRevision", "TargetRevision"), phase5Digest("targetDigest", "TargetDigest"), phase5Digest("physicalHostIdentityDigest", "PhysicalHostIdentityDigest"), phase5Enum("identityMatch", "IdentityMatch", "yes", "no", "unknown"), phase5Enum("hostKeyMatch", "HostKeyMatch", "yes", "no", "unknown"), phase5Enum("virtualization", "Virtualization", "yes", "no", "unknown"), phase5Enum("networkIsolation", "NetworkIsolation", "yes", "no", "unknown"), phase5Enum("guestOwnership", "GuestOwnership", "yes", "no", "unknown"), phase5Enum("workloadsPresent", "WorkloadsPresent", "yes", "no", "unknown"), discoveryText("architecture", "Architecture", 32), phase5Nonnegative("memoryAvailableBytes", "MemoryAvailableBytes"), phase5Nonnegative("storageAvailableBytes", "StorageAvailableBytes"), phase5Enum("hypervisor", "Hypervisor", "qemu", "unknown"), discoveryText("hypervisorVersion", "HypervisorVersion", 64), phase5Timestamp("observedAt", "ObservedAt")),
		phase5Schema("vegastack-labs.dev/scenario-result", qualificationScenario(), phase5Enum("status", "Status", "passed", "failed", "not-run", "uncertain"), phase5Digest("profileLockDigest", "ProfileLockDigest"), phase5Digest("executableDigest", "ExecutableDigest"), baselineOptionalDigest("artifactDigest", "ArtifactDigest"), phase5Timestamp("startedAt", "StartedAt"), phase5Timestamp("finishedAt", "FinishedAt"), accessStrings("positiveObservationDigests", "PositiveObservationDigests", 64), accessStrings("negativeObservationDigests", "NegativeObservationDigests", 64), baselineOptionalDigest("beforeStateDigest", "BeforeStateDigest"), baselineOptionalDigest("afterStateDigest", "AfterStateDigest"), phase5Enum("recoveryResult", "RecoveryResult", "passed", "failed", "not-required", "uncertain"), phase5Enum("cleanupResult", "CleanupResult", "passed", "failed", "not-required", "uncertain"), phase5Enum("qualificationClass", "QualificationClass", "native", "fixture"), accessStrings("producerRunIds", "ProducerRunIDs", 64), accessStrings("producerReceiptDigests", "ProducerReceiptDigests", 64), accessStrings("nativeObservationDigests", "NativeObservationDigests", 64)),
		phase5Schema("vegastack-labs.dev/native-report", accessBool("changed", "Changed"), phase5ID("runId", "RunID"), phase5Digest("scopeDigest", "ScopeDigest"), FieldDefinition{JSONName: "sourceCommit", GoName: "SourceCommit", Kind: ValueString, Required: true, Pattern: "^[0-9a-f]{40}$"}, phase5Digest("executableDigest", "ExecutableDigest"), phase5Digest("profileLockDigest", "ProfileLockDigest"), accessList("scenarios", "Scenarios", "vegastack-labs.dev/scenario-result", 128), accessStrings("pendingRequirements", "PendingRequirements", 128), phase5Timestamp("startedAt", "StartedAt"), phase5Timestamp("finishedAt", "FinishedAt")),
		phase5Schema("vegastack-labs.dev/qualification-inspect-request", phase5ID("targetId", "TargetID"), phase5Positive("targetRevision", "TargetRevision"), phase5Digest("targetDigest", "TargetDigest"), discoveryRef("scope", "Scope", qualificationScopeID), phase5Nonnegative("expectedStateRevision", "ExpectedStateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch")),
		phase5Schema("vegastack-labs.dev/qualification-inspect-data", discoveryRef("facts", "Facts", "vegastack-labs.dev/suitability-facts"), phase5Digest("requestDigest", "RequestDigest"), phase5Nonnegative("stateRevision", "StateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch")),
		phase5Schema("vegastack-labs.dev/native-producer-lookup-request", phase5Digest("scopeDigest", "ScopeDigest"), qualificationScenario(), phase5ID("hostId", "HostID"), phase5ID("planId", "PlanID"), phase5Digest("planDigest", "PlanDigest"), phase5ID("runId", "RunID"), phase5ID("stepId", "StepID"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch")),
		phase5Schema("vegastack-labs.dev/native-producer-reference", qualificationScenario(), phase5ID("hostId", "HostID"), phase5ID("planId", "PlanID"), phase5Digest("planDigest", "PlanDigest"), phase5ID("runId", "RunID"), phase5ID("stepId", "StepID"), phase5ID("leaseId", "LeaseID")),
		phase5Schema("vegastack-labs.dev/native-producer-lookup-data", discoveryRef("producerReference", "ProducerReference", "vegastack-labs.dev/native-producer-reference"), nativeOptionalRef("actionBundle", "ActionBundle", "host-action-bundle")),
		phase5Schema("vegastack-labs.dev/native-collect-request", phase5Digest("scopeDigest", "ScopeDigest"), phase5Enum("stage", "Stage", "baseline", "role", "recovery"), phase5ID("evidenceId", "EvidenceID"), phase5ID("profileId", "ProfileID"), accessList("producers", "Producers", "vegastack-labs.dev/native-producer-reference", 48), phase5Nonnegative("expectedStateRevision", "ExpectedStateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), phase5ID("idempotencyKey", "IdempotencyKey")),

		phase5Schema(qualificationScopeID, phase5ID("runId", "RunID"), phase5Enum("purpose", "Purpose", "native-debian"), phase5ID("controllerInstanceId", "ControllerInstanceID"), phase5Positive("controlServiceUid", "ControlServiceUID"), phase5Positive("controlServiceGid", "ControlServiceGID"), phase5ID("physicalHostId", "PhysicalHostID"), FieldDefinition{JSONName: "physicalHostBootId", GoName: "PhysicalHostBootID", Kind: ValueString, Required: true, Pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"}, phase5Digest("physicalHostIdentityDigest", "PhysicalHostIdentityDigest"), FieldDefinition{JSONName: "sourceCommit", GoName: "SourceCommit", Kind: ValueString, Required: true, Pattern: "^[0-9a-f]{40}$"}, phase5Digest("executableDigest", "ExecutableDigest"), phase5Digest("imageDigest", "ImageDigest"), phase5ID("profileId", "ProfileID"), phase5Digest("profileLockDigest", "ProfileLockDigest"), phase5Digest("consoleReferenceDigest", "ConsoleReferenceDigest"), discoveryText("outputRoot", "OutputRoot", 512), qualificationDuration(), phase5Timestamp("issuedAt", "IssuedAt"), phase5Timestamp("expiresAt", "ExpiresAt"), discoveryRef("resources", "Resources", "vegastack-labs.dev/qualification-resources"), accessList("guests", "Guests", "vegastack-labs.dev/qualification-guest", 4)),
		phase5Schema("vegastack-labs.dev/qualification-resources", phase5Positive("cpus", "CPUs"), phase5Positive("memoryBytes", "MemoryBytes"), phase5Positive("storageBytes", "StorageBytes")),
		phase5Schema("vegastack-labs.dev/qualification-guest", FieldDefinition{JSONName: "machineId", GoName: "MachineID", Kind: ValueString, OmitEmpty: true, Pattern: "^[0-9a-f]{32}$"}, phase5ID("guestId", "GuestID"), phase5ID("hostId", "HostID"), phase5Digest("hostIdentityDigest", "HostIdentityDigest"), phase5ID("instanceId", "InstanceID"), phase5Digest("sshHostKeyDigest", "SSHHostKeyDigest"), phase5Enum("role", "Role", "controller", "subject", "custodian", "replacement"), phase5ID("snapshotId", "SnapshotID"), phase5Digest("diskDigest", "DiskDigest"), phase5Digest("firmwareDigest", "FirmwareDigest"), phase5Positive("cpus", "CPUs"), phase5Positive("memoryBytes", "MemoryBytes"), phase5Positive("diskBytes", "DiskBytes")),
		phase5Schema("vegastack-labs.dev/native-step-request", step...),
		phase5Schema("vegastack-labs.dev/native-observation-binding", binding...),
		phase5Schema("vegastack-labs.dev/native-observation", nativeOptionalRef("credential", "Credential", "native-credential-witness"), nativeOptionalRef("replacementRecovery", "ReplacementRecovery", "native-replacement-recovery-witness"), discoveryRef("binding", "Binding", "vegastack-labs.dev/native-observation-binding"), phase5ID("bootId", "BootID"), phase5Positive("qemuPid", "QEMUPID"), phase5Positive("qemuStartTimeTicks", "QEMUStartTimeTicks"), phase5Digest("executableDigest", "ExecutableDigest"), phase5Digest("diskDigest", "DiskDigest"), phase5Digest("firmwareDigest", "FirmwareDigest"), phase5Timestamp("observedAt", "ObservedAt"), phase5Enum("processState", "ProcessState", "running", "stopped"), phase5Enum("consoleState", "ConsoleState", "healthy", "unavailable"), phase5Digest("channelDigest", "ChannelDigest"), nativeOptionalRef("actionReceiptBefore", "ActionReceiptBefore", "native-action-receipt-witness"), nativeOptionalRef("actionReceiptAfter", "ActionReceiptAfter", "native-action-receipt-witness"), nativeOptionalRef("actionProtocol", "ActionProtocol", "native-action-protocol-witness"), nativeOptionalRef("rollbackBefore", "RollbackBefore", "native-rollback-witness"), nativeOptionalRef("rollbackAfter", "RollbackAfter", "native-rollback-witness"), nativeOptionalRef("fail2banCycle", "Fail2banCycle", "native-fail2ban-witness"), nativeOptionalRef("volumeSeal", "VolumeSeal", "native-volume-seal-witness"), nativeOptionalRef("volumeCase", "VolumeCase", "native-volume-case-witness"), nativeOptionalRef("controlHandoff", "ControlHandoff", "native-control-handoff-witness"), nativeOptionalRef("controlSetup", "ControlSetup", "native-control-setup-witness")),
		phase5Schema("vegastack-labs.dev/native-guest-launch", phase5Digest("scopeDigest", "ScopeDigest"), phase5ID("guestId", "GuestID"), phase5Positive("qemuPid", "QEMUPID"), phase5Positive("qemuStartTimeTicks", "QEMUStartTimeTicks"), phase5Digest("qemuExecutableDigest", "QEMUExecutableDigest"), phase5Digest("diskDigest", "DiskDigest"), phase5Digest("firmwareDigest", "FirmwareDigest"), phase5Digest("consoleReferenceDigest", "ConsoleReferenceDigest")),
		phase5Schema("vegastack-labs.dev/native-step-result", nativeOptionalRef("run", "Run", "run-presentation"), nativeOptionalRef("controllerIdentity", "ControllerIdentity", "native-controller-identity"), nativeOptionalRef("restoreBinding", "RestoreBinding", "restore-binding"), nativeOptionalRef("replacementRecovery", "ReplacementRecovery", "native-replacement-recovery-witness"), nativeOptionalRef("preparation", "Preparation", "native-preparation-result"), nativeOptionalRef("actionReceipt", "ActionReceipt", "native-action-receipt-witness"), accessBool("changed", "Changed"), discoveryRef("binding", "Binding", "vegastack-labs.dev/native-step-request"), phase5Enum("status", "Status", "completed", "awaiting-fixture", "failed"), accessStrings("observationDigests", "ObservationDigests", 64), accessStrings("receiptDigests", "ReceiptDigests", 64), accessStrings("producerRunIds", "ProducerRunIDs", 64), nativeOptionalRef("rollback", "Rollback", "native-rollback-witness"), nativeOptionalRef("fail2banState", "Fail2banState", "native-fail2ban-state"), nativeOptionalRef("ssh", "SSH", "native-ssh-observation"), nativeOptionalRef("volumeSeal", "VolumeSeal", "native-volume-seal-witness"), nativeOptionalRef("volumeCase", "VolumeCase", "native-volume-case-witness"), nativeOptionalRef("controlHandoff", "ControlHandoff", "native-control-handoff-witness"), nativeOptionalRef("controlSetup", "ControlSetup", "native-control-setup-witness"), FieldDefinition{JSONName: "collection", GoName: "Collection", Kind: ValueObject, Ref: "vegastack-labs.dev/native-collect-data", Nullable: true, OmitEmpty: true}),
	}
}

func qualificationCommands() []CommandDefinition {
	specs := []struct {
		name, request, response string
		risk                    RiskClass
	}{
		{"inspect", "vegastack-labs.dev/qualification-inspect-request", "vegastack-labs.dev/qualification-inspect-data", RiskReadOnly},
		{"native", qualificationScopeID, "vegastack-labs.dev/native-report", RiskMutation},
		{"step", "vegastack-labs.dev/native-step-request", "vegastack-labs.dev/native-step-result", RiskMutation},
	}
	var out []CommandDefinition
	for _, s := range specs {
		c := phase5GateCommand([]string{"qualification", s.name}, "Run one finite scoped native qualification workflow.", s.request, s.response, s.risk, []FlagDefinition{{Name: "--config", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read the protected local server profile."}, {Name: "--file", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read a bounded exact qualification request."}}, []string{"qualification", s.name, "--config", "fixture/server-profile.json", "--file", "fixture/qualification.json", "--output", "json"})
		if s.name == "native" {
			c.Flags[0].Summary = "Use the fixed guest client profile /etc/vsk-labs/native/client.json; the outer coordinator does not open a database."
			c.Examples[0].Arguments[3] = "/etc/vsk-labs/native/client.json"
		}
		c.OwnerPhase = "6"
		out = append(out, c)
	}
	peer := phase5GateCommand([]string{"qualification", "fixture-peer"}, "Serve the finite disposable qualification approval peer from its fixed protected manifest until its original deadline.", "", "", RiskMutation, nil, []string{"qualification", "fixture-peer", "--output", "json"})
	peer.OwnerPhase = "6"
	out = append(out, peer)
	return out
}
func qualificationEndpoints() []EndpointDefinition {
	out := []EndpointDefinition{
		phase5Endpoint("api.v1.qualification.producer", "POST", "/api/v1/qualification/native/producer", "vegastack-labs.dev/native-producer-lookup-request", "vegastack-labs.dev/native-producer-lookup-data", false),
		phase5Endpoint("api.v1.qualification.inspect", "POST", "/api/v1/qualification/inspect", "vegastack-labs.dev/qualification-inspect-request", "vegastack-labs.dev/qualification-inspect-data", false),
		phase5Endpoint("api.v1.qualification.collect", "POST", "/api/v1/qualification/collect", "vegastack-labs.dev/native-collect-request", "vegastack-labs.dev/native-collect-data", false),
	}
	for i := range out {
		if out[i].ID == "api.v1.qualification.producer" {
			out[i].TransportScope = "local"
			out[i].MaxRequestBytes = 8192
			out[i].Audiences = []EndpointAudience{AudienceOperator}
		}
		out[i].OwnerPhase = "6"
		out[i].Availability = AvailabilityAvailable
	}
	return out
}

func qualificationDuration() FieldDefinition {
	f := phase5Positive("maximumDurationSeconds", "MaximumDurationSeconds")
	f.Maximum = int64Pointer(14400)
	return f
}

func qualificationScenario() FieldDefinition {
	return phase5Enum("scenarioId", "ScenarioID", "baseline-access", "baseline-controls", "access-idempotence", "access-rollback-timeout", "access-rollback-reboot", "action-replay", "action-concurrency", "fail2ban-window", "container-network", "volume-effective-mapping", "volume-recovery-positive", "volume-wrong-key", "volume-wrong-header", "volume-wrong-slot", "volume-wrong-mapping", "volume-revoked-binding", "volume-unchanged-after-verification", "volume-inconsistent-redundant-header", "volume-status-no-original-repair", "volume-sealed-copy-write-refused", "native-credential-lifecycle", "control-setup", "control-handoff", "role-application", "role-ci", "role-reserve", "replacement-recovery")
}

// NativeQualificationScenarios is the single finite stage catalog.
func NativeQualificationScenarios(stage string) []string {
	var out []string
	for _, scenario := range qualificationScenario().Enum {
		group := "baseline"
		switch scenario {
		case "control-setup", "control-handoff", "role-application", "role-ci", "role-reserve":
			group = "role"
		case "replacement-recovery":
			group = "recovery"
		}
		if group == stage {
			out = append(out, scenario)
		}
	}
	return out
}

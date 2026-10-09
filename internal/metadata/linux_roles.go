package metadata

const linuxRoleInputID = "vegastack-labs.dev/linux-role-input"
const hostRoleScopeID = "vegastack-labs.dev/host-role-scope"

func linuxRoleSchemas() []SchemaDefinition {
	binding := []FieldDefinition{phase5ID("profileId", "ProfileID"), phase5Digest("profileLockDigest", "ProfileLockDigest"), phase5Enum("roleId", "RoleID", "control", "application", "ci", "recovery-spare", "reserve"), accessStrings("controlIds", "ControlIDs", 6), accessStrings("affectedBaselineControlIds", "AffectedBaselineControlIDs", 16), baselineOptionalDigest("baselineSnapshotDigest", "BaselineSnapshotDigest"), baselineOptionalDigest("currentRoleBindingDigest", "CurrentRoleBindingDigest"), phase5Digest("roleBindingDigest", "RoleBindingDigest"), accessBool("networkingRequired", "NetworkingRequired"), accessBool("standbyRequired", "StandbyRequired")}
	input := append([]FieldDefinition{phase5ID("hostId", "HostID"), phase5Digest("hostIdentityDigest", "HostIdentityDigest")}, binding...)
	input = append(input, FieldDefinition{JSONName: "networkAccess", GoName: "NetworkAccess", Kind: ValueObject, Nullable: true, OmitEmpty: true, Ref: "vegastack-labs.dev/debian-access-input"}, accessRef("profileLock", "ProfileLock", "debian-profile-lock"), phase5Version("actionVersion", "ActionVersion"), phase5Positive("automationUid", "AutomationUID"), accessList("accounts", "Accounts", "vegastack-labs.dev/linux-role-account", 2), accessList("directories", "Directories", "vegastack-labs.dev/linux-role-directory", 4), accessRef("resources", "Resources", "linux-role-resources"), phase5Digest("renderedPolicyDigest", "RenderedPolicyDigest"), phase5Digest("executableDigest", "ExecutableDigest"), phase5Digest("configDigest", "ConfigDigest"), phase5Enum("expectedServiceState", "ExpectedServiceState", "absent", "inactive", "active"), baselineOptionalDigest("expectedUnitDigest", "ExpectedUnitDigest"), baselineOptionalDigest("expectedTmpfilesDigest", "ExpectedTmpfilesDigest"), FieldDefinition{JSONName: "handoff", GoName: "Handoff", Kind: ValueObject, Nullable: true, OmitEmpty: true, Ref: "vegastack-labs.dev/control-handoff-input"})
	scopeBinding := append([]FieldDefinition(nil), binding...)
	for i := range scopeBinding {
		if scopeBinding[i].JSONName == "baselineSnapshotDigest" {
			scopeBinding[i] = phase5Digest("baselineSnapshotDigest", "BaselineSnapshotDigest")
		}
	}
	scope := append([]FieldDefinition{phase5ID("subjectHostId", "SubjectHostID"), phase5Digest("subjectIdentityDigest", "SubjectIdentityDigest"), phase5ID("executionHostId", "ExecutionHostID"), phase5Digest("executionIdentityDigest", "ExecutionIdentityDigest")}, scopeBinding...)
	return []SchemaDefinition{
		phase5Schema("vegastack-labs.dev/host-role-foundation", phase5ID("roleId", "RoleID"), baselineOptionalDigest("roleBindingDigest", "RoleBindingDigest"), phase5Enum("status", "Status", "unconfigured", "pending", "installed", "partial", "recovery-required"), phase5Enum("serviceState", "ServiceState", "not-applicable", "pending-handoff", "unverified", "active"), accessStrings("blockers", "Blockers", 32)),
		phase5Schema("vegastack-labs.dev/role-preparation", accessRef("input", "Input", "linux-role-input"), accessList("files", "Files", "vegastack-labs.dev/role-prepared-file", 8), phase5Digest("policyDigest", "PolicyDigest"), FieldDefinition{JSONName: "steps", GoName: "Steps", Kind: ValueArray, Required: true, ItemKind: ValueString, MaxItems: intPointer(16)}),
		phase5Schema("vegastack-labs.dev/role-prepared-file", discoveryText("path", "Path", 256), discoveryText("content", "Content", 8192), phase5Digest("digest", "Digest")),
		phase5Schema(linuxRoleInputID, input...), phase5Schema(hostRoleScopeID, scope...),
		phase5Schema("vegastack-labs.dev/linux-role-account", phase5Enum("selector", "Selector", "control", "application", "ci", "standby"), phase5Positive("uid", "UID"), phase5Positive("gid", "GID"), accessBool("existing", "Existing")),
		phase5Schema("vegastack-labs.dev/linux-role-directory", phase5Enum("selector", "Selector", "config", "state", "runtime", "work"), phase5Positive("uid", "UID"), phase5Positive("gid", "GID"), phase5Enum("mode", "Mode", "0700", "0750"), phase5Enum("expectedState", "ExpectedState", "absent", "owned"), baselineOptionalDigest("expectedDigest", "ExpectedDigest")),
		phase5Schema("vegastack-labs.dev/linux-role-resources", phase5Positive("memoryMaxBytes", "MemoryMaxBytes"), phase5Positive("cpuQuotaPercent", "CPUQuotaPercent"), phase5Positive("tasksMax", "TasksMax"), phase5Positive("minimumFreeBytes", "MinimumFreeBytes"), phase5Positive("minimumFreePercent", "MinimumFreePercent"), phase5Positive("capacityMemoryBytes", "CapacityMemoryBytes"), phase5Positive("capacityCpuPercent", "CapacityCPUPercent"), phase5Positive("capacityTasks", "CapacityTasks")),
		phase5Schema("vegastack-labs.dev/control-handoff-input", phase5Positive("foregroundPid", "ForegroundPID"), phase5ID("foregroundStartIdentity", "ForegroundStartIdentity"), phase5Positive("serviceUid", "ServiceUID"), phase5ID("databaseInstanceId", "DatabaseInstanceID"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"), phase5Digest("writerLockDigest", "WriterLockDigest"), phase5Digest("unitDigest", "UnitDigest"), phase5Digest("configDigest", "ConfigDigest"), phase5Digest("executableDigest", "ExecutableDigest"), phase5Digest("socketIdentityDigest", "SocketIdentityDigest"), phase5Timestamp("expiresAt", "ExpiresAt"), phase5Timestamp("rollbackDeadline", "RollbackDeadline")),
	}
}

func linuxRoleCommands() []CommandDefinition {
	node := phase5GateCommand([]string{"node", "role", "prepare"}, "Prepare an inert role action draft; exact approval and apply remain separate.", hostActionRequestID, hostActionSubmissionID, RiskMutation, []FlagDefinition{{Name: "--config", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read one protected server profile."}, {Name: "--file", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read one exact host-action request JSON file (128 KiB max)."}}, []string{"node", "role", "prepare", "--config", "fixture/server-profile.json", "--file", "fixture/role-action.json", "--output", "json"})
	server := phase5GateCommand([]string{"server", "prepare"}, "Render inert Linux role prerequisites without filesystem or database mutation.", linuxRoleInputID, "vegastack-labs.dev/role-preparation", RiskReadOnly, []FlagDefinition{{Name: "--file", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read one bounded Linux role input JSON file (32 KiB max)."}}, []string{"server", "prepare", "--file", "fixture/role-input.json", "--output", "json"})
	node.OwnerPhase = "6"
	server.OwnerPhase = "6"
	return []CommandDefinition{node, server}
}

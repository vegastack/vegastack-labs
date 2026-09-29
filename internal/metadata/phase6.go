package metadata

// Phase 6 host-lifecycle contracts: public shapes for host identity, node
// roles/aliases, OS-profile applicability and host-hardening evidence. The core
// contract is provider-neutral (no GitHub/Cloudflare/Coolify/Harbor/etc.); the
// concrete role and OS values here (e.g. hermes, mac-developer, debian, macos)
// are VegaStack Labs deployment-profile shapes under the vegastack-labs.dev/
// namespace, like the existing phase-5 profile schemas. They are inert metadata:
// defining them contacts no host, installs nothing, and asserts no admission.
// Concrete Debian/macOS settings and the Ansible execution paths are later
// Phase 6 issues; only the shapes live here.
const (
	hostIdentitySchemaID              = "vegastack-labs.dev/host-identity"
	hostRoleSchemaID                  = "vegastack-labs.dev/host-role"
	hostRoleAliasSchemaID             = "vegastack-labs.dev/host-role-alias"
	hostProfileSchemaID               = "vegastack-labs.dev/host-profile"
	hostHardeningEvidenceFactSchemaID = "vegastack-labs.dev/host-hardening-evidence-fact"
)

// phase6HostSchemas returns the Phase 6 host-lifecycle schema definitions. Each
// carries a schema/schemaVersion envelope at 1.0.0, following the phase 5 pattern.
func phase6HostSchemas() []SchemaDefinition {
	return []SchemaDefinition{
		// host-identity: a managed host as a typed subject, physical or qualified
		// virtual, optionally bound to an inventory asset. No hardware fact is
		// inferred; assetId is nullable so a non-Labs host needs no Labs asset.
		phase5Schema(hostIdentitySchemaID,
			phase5ID("hostId", "HostID"),
			phase5Enum("identityClass", "IdentityClass", "physical", "qualified-virtual"),
			phase5NullableID("assetId", "AssetID"),
			phase5Nonnegative("stateRevision", "StateRevision"),
		),
		// host-profile: which hardening/role profile applies to an OS/version/arch.
		// osFamily is the qualified v1 set (Debian, macOS); Ubuntu is parked.
		phase5Schema(hostProfileSchemaID,
			phase5ID("profileId", "ProfileID"),
			phase5Enum("osFamily", "OSFamily", "debian", "macos"),
			phase6OSVersion("osVersion", "OSVersion"),
			phase5Enum("architecture", "Architecture", "amd64", "arm64"),
			phase5ID("roleId", "RoleID"),
			phase5Version("definitionVersion", "DefinitionVersion"),
		),
		// host-role: the workload role a host may hold once admitted, and the
		// admission gate that role requires.
		phase5Schema(hostRoleSchemaID,
			phase5ID("roleId", "RoleID"),
			phase5Enum("roleClass", "RoleClass",
				"control-plane", "application", "ci", "mac-developer", "hermes", "spare", "reserve"),
			phase5ID("admissionGateId", "AdmissionGateID"),
		),
		// host-role-alias: a stable operator-facing alias (e.g. a node label) for a
		// role binding. The alias value never grants authority.
		phase5Schema(hostRoleAliasSchemaID,
			phase5ID("aliasId", "AliasID"),
			phase5ID("roleId", "RoleID"),
			phase6AliasValue("value", "Value"),
		),
		// host-hardening-evidence-fact: the fact content a hardening/admission proof
		// carries. It is submitted inside the standard gate-evidence envelope; the
		// gate definition points at that envelope, this schema shapes the fact.
		phase5Schema(hostHardeningEvidenceFactSchemaID,
			phase5ID("hostId", "HostID"),
			phase5ID("profileId", "ProfileID"),
			phase5Enum("osFamily", "OSFamily", "debian", "macos"),
			phase5Version("baselineVersion", "BaselineVersion"),
			phase5Nonnegative("controlsPassed", "ControlsPassed"),
			phase5Positive("controlsTotal", "ControlsTotal"),
			phase5Digest("resultDigest", "ResultDigest"),
			phase5Timestamp("observedAt", "ObservedAt"),
			phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"),
		),
	}
}

func phase6OSVersion(name, goName string) FieldDefinition {
	return FieldDefinition{JSONName: name, GoName: goName, Kind: ValueString, Required: true, Pattern: `^[0-9]+(\.[0-9]+){0,3}$`, MinLength: intPointer(1), MaxLength: intPointer(32)}
}

func phase6AliasValue(name, goName string) FieldDefinition {
	return FieldDefinition{JSONName: name, GoName: goName, Kind: ValueString, Required: true, Pattern: `^[a-z0-9][a-z0-9-]{0,63}$`}
}

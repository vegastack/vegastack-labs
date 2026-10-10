package metadata

// The one finite receive action signs exact canonical input. Database and
// journal bytes follow existing host-action authorization; no field selects a
// filesystem path, network address, command, or arbitrary upload kind.
func controlRecoveryReceiveSchemas() []SchemaDefinition {
	size := func(name, goName string, max int64) FieldDefinition {
		f := phase5Positive(name, goName)
		f.Maximum = int64Pointer(max)
		return f
	}
	return []SchemaDefinition{phase5Schema("vegastack-labs.dev/control-recovery-receive-input",
		discoveryRef("binding", "Binding", "vegastack-labs.dev/restore-binding"),
		discoveryRef("replacement", "Replacement", "vegastack-labs.dev/host-replacement-request"),
		phase5Enum("destinationIdentityKind", "DestinationIdentityKind", "product-serial", "product-uuid"),
		size("candidateBytes", "CandidateBytes", 536870912), phase5Digest("candidateBytesDigest", "CandidateBytesDigest"), phase5Digest("databaseDigest", "DatabaseDigest"),
		size("journalBytes", "JournalBytes", 32768), phase5Digest("journalDigest", "JournalDigest"), phase5Digest("bundleDigest", "BundleDigest"),
		size("serviceUid", "ServiceUID", 4294967295), size("serviceGid", "ServiceGID", 4294967295), discoveryRef("roleInput", "RoleInput", "vegastack-labs.dev/linux-role-input"),
	)}
}

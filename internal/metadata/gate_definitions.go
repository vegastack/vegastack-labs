package metadata

import "fmt"

// GateDefinitionSource is generated platform metadata, not an evaluation or
// admission assertion. A profile ID scopes concrete deployment gates; an empty
// profile ID denotes an always-applicable portable safety definition.
type GateDefinitionSource struct {
	GateID, DefinitionVersion, Layer, ProfileID, CapabilityID, Applicability string
	SubjectKinds, PrerequisiteGateIDs                                        []string
	EvidenceSchemaID, EvaluatorVersion                                       string
	FreshnessSeconds                                                         int64
	RecoveryEpochBound                                                       bool
}

func CurrentGateDefinitions() []GateDefinitionSource {
	definitions := []GateDefinitionSource{{
		GateID: "platform-safety", DefinitionVersion: "1.0.0", Layer: "platform",
		Applicability: "always", SubjectKinds: []string{"site", "node", "service"},
		PrerequisiteGateIDs: []string{}, EvidenceSchemaID: gateEvidenceSchemaID,
		EvaluatorVersion: "1.0.0", FreshnessSeconds: 3600, RecoveryEpochBound: true,
	}}
	// This catalog is selected only by the VegaStack Labs deployment profile.
	// It is not a mandatory checklist for a minimal/no-account installation.
	for number := 1; number <= 23; number++ {
		id := fmt.Sprintf("G-%03d", number)
		definition := GateDefinitionSource{
			GateID: id, DefinitionVersion: "1.0.0", Layer: "deployment-profile",
			ProfileID: "vegastack-labs", Applicability: "profile",
			SubjectKinds: []string{"site"}, PrerequisiteGateIDs: []string{},
			EvidenceSchemaID: gateEvidenceSchemaID, EvaluatorVersion: "1.0.0",
			FreshnessSeconds: 86400, RecoveryEpochBound: true,
		}
		switch number {
		case 2, 9, 10, 20, 21:
			definition.SubjectKinds = []string{"node"}
		case 16:
			definition.SubjectKinds = []string{"adapter"}
		case 19, 22, 23:
			definition.SubjectKinds = []string{"service"}
		}
		if number == 8 {
			definition.PrerequisiteGateIDs = []string{"platform-safety"}
		}
		if number == 22 {
			definition.Applicability = "capability"
			definition.CapabilityID = "service-admission"
		}
		if number == 23 {
			definition.Applicability = "deferred"
		}
		definitions = append(definitions, definition)
	}
	definitions = append(definitions, phase6HostGateDefinitions()...)
	for _, stage := range []string{"baseline", "role", "recovery"} {
		definitions = append(definitions, GateDefinitionSource{GateID: "native." + stage, DefinitionVersion: "1.0.0", Layer: "platform", Applicability: "always", SubjectKinds: []string{"profile"}, PrerequisiteGateIDs: []string{}, EvidenceSchemaID: gateEvidenceSchemaID, EvaluatorVersion: "1.0.0", FreshnessSeconds: 86400, RecoveryEpochBound: true})
	}
	return definitions
}

// phase6HostGateDefinitions returns the host hardening and role-admission gates.
// Every managed host (node subject) will need a hardening baseline before role
// admission. The definitions remain deferred until Issue 6.8 binds exact host
// profile and control facts to applied evidence; a generic gate proof cannot
// admit a host. Slug IDs leave the G-001..G-023 ledger unchanged.
func phase6HostGateDefinitions() []GateDefinitionSource {
	return []GateDefinitionSource{
		{
			GateID: "host.hardening-baseline", DefinitionVersion: "1.1.0", Layer: "platform",
			Applicability: "always", SubjectKinds: []string{"node"},
			PrerequisiteGateIDs: []string{"platform-safety"}, EvidenceSchemaID: gateEvidenceSchemaID,
			EvaluatorVersion: "1.1.0", FreshnessSeconds: 86400, RecoveryEpochBound: true,
		},
		{
			GateID: "host.role-admission", DefinitionVersion: "1.1.0", Layer: "platform",
			Applicability: "always", SubjectKinds: []string{"node"},
			PrerequisiteGateIDs: []string{"host.hardening-baseline"}, EvidenceSchemaID: gateEvidenceSchemaID,
			EvaluatorVersion: "1.1.0", FreshnessSeconds: 86400, RecoveryEpochBound: true,
		},
	}
}

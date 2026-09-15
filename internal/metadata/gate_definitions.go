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
	return definitions
}

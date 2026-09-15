// Package gate derives readiness from generated definitions and server-owned
// applied bindings. It never stores a passed flag or accepts a caller assertion.
package gate

import (
	"slices"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

type Definition struct {
	ID, Version, Layer, ProfileID, CapabilityID, Applicability string
	SubjectKinds, PrerequisiteIDs                              []string
	EvidenceSchemaID, EvaluatorVersion                         string
	FreshnessSeconds                                           int64
	RecoveryEpochBound                                         bool
}

type ResolvedScope struct {
	ProfileID, ProfileVersion, PolicyID, PolicyVersion string
	Capabilities                                       []string
	StateRevision, RecoveryEpoch                       int64
}

type ApplicableDefinition struct {
	Definition Definition
	Applicable bool
	ReasonCode string
}

func ResolveDefinitions(scope ResolvedScope, subjectKind string) []ApplicableDefinition {
	if scope.ProfileID == "" || scope.ProfileVersion == "" || scope.PolicyID == "" || scope.PolicyVersion == "" || subjectKind == "" {
		return nil
	}
	definitions := make([]ApplicableDefinition, 0, len(generated.GeneratedGateDefinitions))
	for _, source := range generated.GeneratedGateDefinitions {
		if !slices.Contains(source.SubjectKinds, subjectKind) {
			continue
		}
		definition := Definition{
			ID: source.GateID, Version: source.DefinitionVersion, Layer: source.Layer,
			Applicability: source.Applicability, SubjectKinds: append([]string(nil), source.SubjectKinds...),
			PrerequisiteIDs:  append([]string(nil), source.PrerequisiteGateIDs...),
			EvidenceSchemaID: source.EvidenceSchemaID, EvaluatorVersion: source.EvaluatorVersion,
			FreshnessSeconds: source.FreshnessSeconds, RecoveryEpochBound: source.RecoveryEpochBound,
		}
		if source.ProfileID != nil {
			definition.ProfileID = *source.ProfileID
		}
		if source.CapabilityID != nil {
			definition.CapabilityID = *source.CapabilityID
		}
		item := ApplicableDefinition{Definition: definition, Applicable: true, ReasonCode: "applicable"}
		switch {
		case source.Applicability == "deferred":
			item.Applicable, item.ReasonCode = false, "deferred"
		case definition.ProfileID != "" && definition.ProfileID != scope.ProfileID:
			item.Applicable, item.ReasonCode = false, "profile-not-selected"
		case source.Applicability == "capability" && !slices.Contains(scope.Capabilities, definition.CapabilityID):
			item.Applicable, item.ReasonCode = false, "capability-disabled"
		}
		definitions = append(definitions, item)
	}
	return definitions
}

func HasApplicable(items []ApplicableDefinition, gateID string) bool {
	for _, item := range items {
		if item.Definition.ID == gateID {
			return item.Applicable
		}
	}
	return false
}

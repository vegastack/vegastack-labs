package gate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

type Subject struct {
	ID, Kind, ReleaseBuildID, ToolVersion, DeclarationID, ArtifactDigest string
	DeclarationRevision, StateRevision                                   int64
}

type EvidenceReader interface {
	ListAppliedGateEvidence(context.Context, string, string) ([]generated.GateEvidence, error)
}

// CurrentEvidenceReader is the read-only exact-current view used by recovery
// scope composition. Historical evidence remains available through
// EvidenceReader for audit/display, but cannot become current again after a
// superseding or revoking row is appended.
type CurrentEvidenceReader interface {
	ListCurrentAppliedGateEvidence(context.Context, string, string) ([]generated.GateEvidence, error)
}

type evaluationContext struct {
	reader      EvidenceReader
	scope       ResolvedScope
	subject     Subject
	at          time.Time
	verifiers   ProofRegistry
	definitions map[string]ApplicableDefinition
	visiting    map[string]bool
	completed   map[string]generated.GateEvaluation
}

func Evaluate(ctx context.Context, reader EvidenceReader, scope ResolvedScope, subject Subject, gateID string, at time.Time, verifiers ProofRegistry) (generated.GateEvaluation, error) {
	state := newEvaluationContext(reader, scope, subject, at, verifiers)
	return state.check(ctx, gateID)
}

func ListReadyForInput(ctx context.Context, reader EvidenceReader, scope ResolvedScope, subject Subject, at time.Time, verifiers ProofRegistry) ([]generated.GateEvaluation, error) {
	state := newEvaluationContext(reader, scope, subject, at, verifiers)
	keys := make([]string, 0, len(state.definitions))
	for key := range state.definitions {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	result := make([]generated.GateEvaluation, 0, len(keys))
	for _, key := range keys {
		item, err := state.check(ctx, key)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, nil
}

func newEvaluationContext(reader EvidenceReader, scope ResolvedScope, subject Subject, at time.Time, verifiers ProofRegistry) *evaluationContext {
	definitions := map[string]ApplicableDefinition{}
	for _, item := range ResolveDefinitions(scope, subject.Kind) {
		definitions[item.Definition.ID] = item
	}
	return &evaluationContext{reader: reader, scope: scope, subject: subject, at: at.UTC(), verifiers: verifiers, definitions: definitions, visiting: map[string]bool{}, completed: map[string]generated.GateEvaluation{}}
}

func (state *evaluationContext) check(ctx context.Context, gateID string) (generated.GateEvaluation, error) {
	if got, ok := state.completed[gateID]; ok {
		return got, nil
	}
	item, known := state.definitions[gateID]
	evaluation := state.base(gateID, item.Definition)
	if !known {
		evaluation.Outcome, evaluation.ReasonCode = "unknown", "definition-unresolved"
		return evaluation, nil
	}
	if !item.Applicable {
		evaluation.Outcome, evaluation.ReasonCode = "not-applicable", item.ReasonCode
		state.completed[gateID] = evaluation
		return evaluation, nil
	}
	if state.visiting[gateID] {
		evaluation.Outcome, evaluation.ReasonCode = "blocked", "prerequisite-cycle"
		return evaluation, nil
	}
	state.visiting[gateID] = true
	defer delete(state.visiting, gateID)
	for _, prerequisiteID := range item.Definition.PrerequisiteIDs {
		prerequisite, err := state.check(ctx, prerequisiteID)
		if err != nil {
			return evaluation, err
		}
		if prerequisite.Outcome != "passed" {
			evaluation.Outcome, evaluation.ReasonCode = "blocked", "prerequisite-not-passed"
			state.completed[gateID] = evaluation
			return evaluation, nil
		}
	}
	evaluation.ReadyForInput = true
	if state.reader == nil {
		evaluation.Outcome, evaluation.ReasonCode = "unknown", "evidence-reader-unavailable"
		return evaluation, nil
	}
	var rows []generated.GateEvidence
	var err error
	if current, ok := state.reader.(CurrentEvidenceReader); ok {
		rows, err = current.ListCurrentAppliedGateEvidence(ctx, gateID, state.subject.ID)
	} else {
		rows, err = state.reader.ListAppliedGateEvidence(ctx, gateID, state.subject.ID)
	}
	if err != nil {
		return evaluation, err
	}
	if len(rows) == 0 {
		evaluation.Outcome, evaluation.ReasonCode = "blocked", "evidence-missing"
		state.completed[gateID] = evaluation
		return evaluation, nil
	}
	replaced := map[string]bool{}
	for _, row := range rows {
		if row.SupersedesEvidenceID != nil {
			replaced[*row.SupersedesEvidenceID] = true
		}
		if row.RevokesEvidenceID != nil {
			replaced[*row.RevokesEvidenceID] = true
		}
	}
	// Newest evidence is tried first; an older proof is not revived after
	// supersession or revocation. State revision is a monotonic append ordinal.
	slices.SortFunc(rows, func(left, right generated.GateEvidence) int {
		if left.StateRevision > right.StateRevision {
			return -1
		}
		if left.StateRevision < right.StateRevision {
			return 1
		}
		if left.EvidenceID > right.EvidenceID {
			return -1
		}
		if left.EvidenceID < right.EvidenceID {
			return 1
		}
		return 0
	})
	for _, row := range rows {
		if len(evaluation.EvidenceIDs) < 64 {
			evaluation.EvidenceIDs = append(evaluation.EvidenceIDs, row.EvidenceID)
		}
		if row.Status == "revoked" {
			continue
		}
		if replaced[row.EvidenceID] {
			continue
		}
		evaluation.EvidenceSource = row.SourceKind
		reason := state.validate(item.Definition, row)
		if reason != "" {
			evaluation.Outcome, evaluation.ReasonCode = "blocked", reason
			continue
		}
		verifier, registered := state.verifiers.Lookup(gateID, row.SourceKind)
		if !registered {
			evaluation.Outcome, evaluation.ReasonCode = "blocked", "proof-unverified"
			continue
		}
		proof, err := verifier.Verify(ctx, item.Definition, row)
		if err != nil {
			return evaluation, err
		}
		if !proof.Verified {
			evaluation.Outcome, evaluation.ReasonCode = "blocked", "proof-rejected"
			continue
		}
		evaluation.Outcome, evaluation.ReasonCode, evaluation.ReadyForInput = "passed", "proof-verified", false
		state.completed[gateID] = evaluation
		return evaluation, nil
	}
	if evaluation.ReasonCode == "" {
		evaluation.Outcome, evaluation.ReasonCode = "blocked", "evidence-revoked-or-replaced"
	}
	state.completed[gateID] = evaluation
	return evaluation, nil
}

func (state *evaluationContext) validate(definition Definition, evidence generated.GateEvidence) string {
	raw, err := json.Marshal(evidence)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDGateEvidence, raw, generated.ContractExact) != nil {
		return "evidence-invalid"
	}
	if evidence.SchemaVersion != "1.1.0" || evidence.Status != "applied" || evidence.SourceKind == "fixture" || evidence.ProofClass != "live" {
		return "evidence-fixture-or-legacy"
	}
	if evidence.GateID != definition.ID || evidence.SubjectID != state.subject.ID {
		return "evidence-wrong-subject"
	}
	if evidence.DefinitionVersion != definition.Version || evidence.EvaluatorVersion != definition.EvaluatorVersion || evidence.ReleaseBuildID != state.subject.ReleaseBuildID || evidence.ToolVersion != state.subject.ToolVersion || evidence.ProfileID != state.scope.ProfileID || evidence.ProfileVersion != state.scope.ProfileVersion || evidence.PolicyID != state.scope.PolicyID || evidence.PolicyVersion != state.scope.PolicyVersion {
		return "evidence-wrong-version"
	}
	if evidence.DeclarationID != state.subject.DeclarationID || evidence.DeclarationRevision != state.subject.DeclarationRevision || evidence.StateRevision != state.subject.StateRevision || evidence.ArtifactDigest != state.subject.ArtifactDigest {
		return "evidence-wrong-revision"
	}
	if evidence.RecoveryEpoch != state.scope.RecoveryEpoch {
		return "evidence-wrong-epoch"
	}
	if evidence.HumanID == "" || evidence.CollectorID == "" || evidence.BundleDigest == "" {
		return "evidence-incomplete"
	}
	observed, observedErr := time.Parse(time.RFC3339, evidence.ObservedAt)
	applied, appliedErr := time.Parse(time.RFC3339, evidence.AppliedAt)
	expires, expiresErr := time.Parse(time.RFC3339, evidence.ExpiresAt)
	if observedErr != nil || appliedErr != nil || expiresErr != nil || observed.After(applied) || applied.After(state.at) || observed.After(state.at) || !expires.After(applied) {
		return "evidence-future-or-invalid-time"
	}
	if !expires.After(state.at) {
		return "evidence-expired"
	}
	if definition.FreshnessSeconds > 0 && state.at.Sub(observed) > time.Duration(definition.FreshnessSeconds)*time.Second {
		return "evidence-stale"
	}
	return ""
}

func (state *evaluationContext) base(gateID string, definition Definition) generated.GateEvaluation {
	version, evaluatorVersion := definition.Version, definition.EvaluatorVersion
	if version == "" {
		version = "1.0.0"
	}
	if evaluatorVersion == "" {
		evaluatorVersion = "1.0.0"
	}
	sum := sha256.Sum256([]byte(gateID + "\x00" + state.subject.ID + "\x00" + state.at.Format(time.RFC3339Nano)))
	return generated.GateEvaluation{Schema: generated.SchemaIDGateEvaluation, SchemaVersion: "1.1.0", EvaluationID: "eval-" + hex.EncodeToString(sum[:12]), GateID: gateID, SubjectID: state.subject.ID, DefinitionVersion: version, EvaluatorVersion: evaluatorVersion, EvidenceIDs: []string{}, EvaluatedAt: state.at.Format(time.RFC3339), RecoveryEpoch: state.scope.RecoveryEpoch, Outcome: "unknown", ReasonCode: "definition-unresolved", EvidenceSource: "none"}
}

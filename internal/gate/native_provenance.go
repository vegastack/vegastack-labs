package gate

import (
	"errors"
	"regexp"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/qualification"
	"github.com/vegastack/vegastack-labs/internal/store"
)

var errNativeProvenance = errors.New("native qualification unavailable")

type nativeHostProvenance struct {
	source, executable string
	clock              func() time.Time
}

// NewNativeHostProvenance takes measured running-build pins, never request
// fields. Verification is pure: the repository supplies the joined lineage.
func NewNativeHostProvenance(source, executable string, clock func() time.Time) (store.HostAdmissionProvenance, error) {
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(source) || !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(executable) || clock == nil {
		return nil, errNativeProvenance
	}
	return nativeHostProvenance{source, executable, clock}, nil
}

func (v nativeHostProvenance) VerifyHostEvidence(s store.HostAdmissionSnapshot, e generated.GateEvidence, b generated.GateEvidenceBundle) (store.HostEvidenceProvenance, error) {
	deny := func() (store.HostEvidenceProvenance, error) {
		return store.HostEvidenceProvenance{}, errNativeProvenance
	}
	q := b.NativeQualification
	joined, exists := s.NativeProducerBindings[e.EvidenceID]
	if q == nil || !exists || !validHostJSON(generated.SchemaIDNativeQualification, *q) || !validHostJSON(generated.SchemaIDGateEvidence, e) || !validHostJSON(generated.SchemaIDGateEvidenceBundle, b) {
		return deny()
	}
	if e.GateID != "native."+q.Stage || len(qualification.StageScenarios(q.Stage)) == 0 || e.Status != "applied" || e.SourceKind != "local" || e.ProofClass != "live" || e.CollectorID != "native-debian-228" || b.CollectorID != e.CollectorID || e.SubjectID != q.ProfileID || e.DefinitionVersion != "1.0.0" || e.EvaluatorVersion != "1.0.0" {
		return deny()
	}
	if q.SourceCommit != v.source || q.ExecutableDigest != v.executable || q.SourceDigest != qualification.SourceDigest(generated.QualificationScope{SourceCommit: v.source, ExecutableDigest: v.executable}) || q.ProfileLockDigest != s.ProfileLockDigest || q.ControllerInstanceID != joined.CurrentControllerInstanceID || q.RecoveryEpoch != s.Revision.RecoveryEpoch || e.RecoveryEpoch != q.RecoveryEpoch || q.ObservedAt != e.ObservedAt || q.ExpiresAt != e.ExpiresAt || b.ObservedAt != e.ObservedAt || !hostEvidenceTime(e, v.clock().UTC()) {
		return deny()
	}
	requiredStages := []string{}
	if q.Stage == "role" {
		requiredStages = []string{"baseline"}
	}
	if q.Stage == "recovery" {
		requiredStages = []string{"baseline", "role"}
	}
	if len(q.Prerequisites) != len(requiredStages) {
		return deny()
	}
	for i, prior := range q.Prerequisites {
		if prior.Stage != requiredStages[i] || prior.EvidenceID == e.EvidenceID || prior.BundleDigest == e.BundleDigest {
			return deny()
		}
	}
	a := joined.Applied
	if hostaction.Digest(joined.Qualification) != hostaction.Digest(*q) || hostaction.Digest(b) != e.BundleDigest || a.BundleDigest != e.BundleDigest || a.ArtifactDigest != e.ArtifactDigest || a.DeclarationID != e.DeclarationID || a.DeclarationRevision != e.DeclarationRevision || a.StateRevision != e.StateRevision || a.RecoveryEpoch != e.RecoveryEpoch || a.ReleaseBuildID != e.ReleaseBuildID || a.ToolVersion != e.ToolVersion || e.ToolVersion != s.ProfileLock.ExecutableVersion {
		return deny()
	}
	if !hostFact(b, "native.profile-lock", q.ProfileLockDigest) || !hostFact(b, "native.source", q.SourceDigest) || !hostCheck(b, "native."+q.Stage, q.SourceDigest) || len(q.Producers) == 0 || len(q.Producers) > 48 || hostaction.Digest(q.Producers) != hostaction.Digest(joined.Producers) || len(joined.Executions) != len(q.Producers) {
		return deny()
	}
	seen := map[string]bool{}
	for i, producer := range q.Producers {
		x := joined.Executions[i]
		if hostaction.Digest(x.Reference) != hostaction.Digest(producer.Reference) || hostaction.Digest(x.Receipt) != producer.ReceiptDigest || x.Plan.PlanID != x.Reference.PlanID || x.Plan.PlanDigest != x.Reference.PlanDigest || x.Receipt.RunID != x.Reference.RunID || x.Receipt.StepID != x.Reference.StepID || x.Receipt.LeaseID != x.Reference.LeaseID {
			return deny()
		}
		seen[x.Reference.ScenarioID] = true
	}
	for _, id := range qualification.StageScenarios(q.Stage) {
		if !seen[id] {
			return deny()
		}
	}
	return store.HostEvidenceProvenance{Qualification: &store.HostNativeQualification{Stage: q.Stage, ProfileDigest: q.ProfileLockDigest, EvidenceID: e.EvidenceID, SourceDigest: q.SourceDigest, ObservedAt: q.ObservedAt, ExpiresAt: q.ExpiresAt, RecoveryEpoch: q.RecoveryEpoch}}, nil
}

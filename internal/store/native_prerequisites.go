package store

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

// Only the fixed preceding stages are considered. Baseline terminates this
// dependency chain; no arbitrary gate graph or future-stage lookup is allowed.
func (r *GateRepository) nativePrerequisites(ctx context.Context, q nativeQuery, p generated.NativeQualification) ([]generated.NativeQualificationPrerequisite, error) {
	var stages []string
	switch p.Stage {
	case "baseline":
		return nil, nil
	case "role":
		stages = []string{"baseline"}
	case "recovery":
		stages = []string{"baseline", "role"}
	default:
		return nil, nativeError()
	}
	if r.hostProvenance == nil {
		return nil, nativeError()
	}
	s := HostAdmissionSnapshot{Profile: generated.HostProfile{ProfileID: p.ProfileID}, ProfileLock: generated.DebianProfileLock{ExecutableVersion: r.store.config.ToolVersion}, ProfileLockDigest: p.ProfileLockDigest, Bundles: map[string]generated.GateEvidenceBundle{}, AppliedBindings: map[string]HostAppliedBinding{}, NativeProducerBindings: map[string]HostNativeProducerBinding{}, PrerequisiteDigests: map[string]string{}, PrerequisiteEvidenceIDs: map[string]string{}}
	if err := q.row(`SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&s.Revision.StateRevision, &s.Revision.RecoveryEpoch); err != nil {
		return nil, err
	}
	if s.Revision.RecoveryEpoch != p.RecoveryEpoch {
		return nil, nativeError()
	}
	gates := make([]string, len(stages))
	for i, stage := range stages {
		gates[i] = "native." + stage
	}
	if err := r.admissionEvidenceStages(ctx, q.tx, &s, gates); err != nil {
		return nil, err
	}
	result := make([]generated.NativeQualificationPrerequisite, 0, len(stages))
	for _, stage := range stages {
		found := false
		for _, qualification := range s.Qualifications {
			if qualification.Stage != stage || qualification.SourceDigest != p.SourceDigest || qualification.ProfileDigest != p.ProfileLockDigest || qualification.RecoveryEpoch != p.RecoveryEpoch {
				continue
			}
			for _, e := range s.Evidence {
				if e.EvidenceID == qualification.EvidenceID && e.Status == "applied" && e.SubjectID == p.ProfileID && e.GateID == "native."+stage {
					result = append(result, generated.NativeQualificationPrerequisite{Schema: generated.SchemaIDNativeQualificationPrerequisite, SchemaVersion: "1.0.0", Stage: stage, EvidenceID: e.EvidenceID, BundleDigest: e.BundleDigest, ArtifactDigest: e.ArtifactDigest})
					found = true
					break
				}
			}
		}
		if !found {
			return nil, nativeError()
		}
	}
	if len(result) != len(stages) {
		return nil, nativeError()
	}
	return result, nil
}
func nativePrerequisitesEqual(a, b []generated.NativeQualificationPrerequisite) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return hostaction.Digest(a) == hostaction.Digest(b)
}

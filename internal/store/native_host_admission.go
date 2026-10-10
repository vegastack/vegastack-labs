package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"slices"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostadoption"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"github.com/vegastack/vegastack-labs/internal/hostreplacement"
)

// NativeCollectSubject selects one inert ordinary gate draft. Host evidence
// cannot replace the full baseline profile qualification or claim physical proof.
func NativeCollectSubject(in generated.NativeCollectRequest) (string, string, bool) {
	if in.HostID == "" && in.HostGateID == "" {
		return "native." + in.Stage, in.ProfileID, true
	}
	if in.HostID == "" || !((in.Stage == "baseline" && slices.Contains([]string{"platform-safety", "host.hardening-baseline"}, in.HostGateID)) || (in.Stage == "role" && in.HostGateID == "host.role-admission")) {
		return "", "", false
	}
	return in.HostGateID, in.HostID, true
}

// NativeHostControlsDigest excludes evidence projections: applying either
// ordinary gate leaves its independently measured control lineage unchanged.
func NativeHostControlsDigest(s HostAdmissionSnapshot) string {
	rows := make([]string, 0, len(s.Measurements))
	for _, m := range s.Measurements {
		rows = append(rows, hostaction.Digest(m))
	}
	slices.Sort(rows)
	return hostaction.Digest(struct {
		Binding        string
		Rows, Blockers []string
	}{s.BindingDigest, rows, s.Blockers})
}

func (r *GateRepository) ResolveNativeHostAdmission(ctx context.Context, hostID string, guest generated.QualificationGuest) (out HostAdmissionSnapshot, discoveryDigest string, err error) {
	if r == nil || r.store == nil || hostID != guest.HostID {
		return out, "", nativeError()
	}
	err = r.store.Read(ctx, func(tx ReadTx) error {
		var e error
		out, e = r.resolveHostAdmission(ctx, tx, hostID)
		if e != nil {
			return e
		}
		discoveryDigest, e = nativeHostDiscovery(ctx, tx, out, guest)
		return e
	})
	return
}

// The independently observed adoption identity and administrator confirmation
// remain anchored to their original immutable record. Fresh console observation
// supplies current boot/liveness; historical discovery alone cannot qualify.
func nativeHostDiscovery(ctx context.Context, tx ReadTx, s HostAdmissionSnapshot, g generated.QualificationGuest) (string, error) {
	row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
	if s.Host.IdentityClass != "qualified-virtual" || s.Host.HostID != g.HostID || s.IdentityDigest != g.HostIdentityDigest || g.MachineID == "" || s.Host.RecoveryEpoch != s.Revision.RecoveryEpoch {
		return "", nativeError()
	}
	obs, err := readDiscoveryObservation(row, s.Host.ObservationID)
	if err != nil {
		return "", nativeError()
	}
	target, err := discoveryTarget(row, s.Host.TargetID)
	if err != nil {
		return "", nativeError()
	}
	var raw []byte
	var digest string
	if row(`SELECT d.canonical_bytes,d.digest FROM managed_hosts h JOIN host_adoption_drafts d ON d.draft_id=h.draft_id WHERE h.host_id=?`, g.HostID).Scan(&raw, &digest) != nil || !nativeContractBytes(generated.SchemaIDHostAdoptionRequest, raw) {
		return "", nativeError()
	}
	var req generated.HostAdoptionRequest
	if json.Unmarshal(raw, &req) != nil || hostadoption.Digest(req) != digest || req.HostID != g.HostID || req.Confirmation.IdentityClass != "qualified-virtual" || req.Confirmation.IdentityKind != "product-serial" || req.Confirmation.IdentityDigest != g.HostIdentityDigest {
		return "", nativeError()
	}
	// Validate the original administrator confirmation against its immutable
	// target revision. Later credential revisions cannot rewrite that record.
	var historicalRaw []byte
	var historicalDigest, historicalStatus string
	if row(`SELECT d.canonical_bytes,d.digest,t.status FROM host_discovery_targets t JOIN host_discovery_drafts d ON d.draft_id=t.draft_id WHERE t.target_id=? AND t.revision=?`, obs.TargetID, obs.TargetRevision).Scan(&historicalRaw, &historicalDigest, &historicalStatus) != nil {
		return "", nativeError()
	}
	var historical generated.HostDiscoveryTargetDraftRequest
	if !nativeContractBytes(generated.SchemaIDHostDiscoveryTargetDraftRequest, historicalRaw) || json.Unmarshal(historicalRaw, &historical) != nil || historicalStatus != "active" || historicalDigest != obs.TargetDigest || hostdiscovery.Digest(historical) != historicalDigest || hostdiscovery.ValidateTarget(historical.Target) != nil || historical.Target.TargetID != target.Binding.TargetID || historical.Target.ProfileID != target.Binding.ProfileID || historical.Target.HostKey != target.Binding.HostKey || target.Binding.RecoveryEpoch != s.Revision.RecoveryEpoch {
		return "", nativeError()
	}
	confirmed, err := time.Parse(time.RFC3339, req.Confirmation.ConfirmedAt)
	if err != nil || hostadoption.Validate(req, obs, historical.Target, confirmed) != nil {
		return "", nativeError()
	}
	keyDigest, err := hostreplacement.SSHHostKeyDigest(target.Binding.HostKey)
	if err != nil || keyDigest != g.SSHHostKeyDigest {
		return "", nativeError()
	}
	facts := map[string]string{}
	for _, f := range obs.Facts {
		facts[f.Name] = f.Value
	}
	if facts["product-serial"] != g.InstanceID || facts["machine-id"] != g.MachineID || hostadoption.IdentityDigest("product-serial", g.InstanceID) != g.HostIdentityDigest {
		return "", nativeError()
	}
	return obs.ContentDigest, nil
}

func nativeContractBytes(schema string, raw []byte) bool {
	return generated.ValidateContractJSON(schema, raw, generated.ContractExact) == nil
}

func nativeHostGuest(p generated.NativeHostProof) (generated.QualificationGuest, bool) {
	var found generated.QualificationGuest
	count := 0
	for _, g := range p.Scope.Guests {
		if g.HostID == p.HostID {
			found = g
			count++
		}
	}
	return found, count == 1 && found.HostIdentityDigest == p.HostIdentityDigest && p.Observation.Binding.GuestID == found.GuestID
}

func nativeAppliedSubjectMatches(e generated.GateEvidence, q *generated.NativeQualification, s HostAdmissionSnapshot) bool {
	if q.HostProof == nil {
		return e.GateID == "native."+q.Stage && e.SubjectID == q.ProfileID
	}
	_, _, valid := NativeCollectSubject(generated.NativeCollectRequest{Stage: q.Stage, HostID: q.HostProof.HostID, HostGateID: e.GateID})
	return valid && e.SubjectID == q.HostProof.HostID && e.SubjectID == s.Host.HostID
}

func nativeHostBundleShape(b generated.GateEvidenceBundle, q generated.NativeQualification) bool {
	expectedFacts := 4
	if q.Stage == "role" {
		expectedFacts = 5
	}
	if q.HostProof == nil || !slices.Contains([]string{"baseline", "role"}, q.Stage) || !nativeContract(generated.SchemaIDNativeHostProof, *q.HostProof) || len(b.Attachments) != 0 || len(b.Facts) != expectedFacts || len(b.Checks) < 2 || len(b.Checks) > 65 {
		return false
	}
	facts := map[string]string{}
	for _, f := range b.Facts {
		if !nativeContract(generated.SchemaIDGateEvidenceFact, f) {
			return false
		}
		if _, ok := facts[f.FactID]; ok {
			return false
		}
		facts[f.FactID] = f.ValueDigest
	}
	if q.Stage == "role" && facts["host.role-binding"] == "" {
		return false
	}
	if facts["native.profile-lock"] != q.ProfileLockDigest || facts["native.source"] != q.SourceDigest || facts["host.binding"] != q.HostProof.HostBindingDigest || facts["host.profile-lock"] != q.ProfileLockDigest {
		return false
	}
	seen := map[string]bool{}
	for _, c := range b.Checks {
		if seen[c.CheckID] || c.Result != "passed" || c.VerifierVersion != "1.0.0" {
			return false
		}
		seen[c.CheckID] = true
		allowed := slices.Contains([]string{"native." + q.Stage, "identity-console", "recovery-access", "qualified-virtual"}, c.CheckID)
		for _, r := range generated.GeneratedHostControlRequirements {
			allowed = allowed || (r.Stage == q.Stage && r.ControlID == c.CheckID)
		}
		if !allowed {
			return false
		}
		if c.CheckID == "native."+q.Stage && c.ResultDigest != q.SourceDigest {
			return false
		}
	}
	return seen["native."+q.Stage]
}

func (r *GateRepository) validateNativeHostProof(ctx context.Context, tx ReadTx, s HostAdmissionSnapshot, q generated.NativeQualification) error {
	p := q.HostProof
	if p == nil || !slices.Contains([]string{"baseline", "role"}, q.Stage) || !nativeContract(generated.SchemaIDNativeHostProof, *p) || p.HostID != s.Host.HostID || p.HostIdentityDigest != s.IdentityDigest || p.HostBindingDigest != s.BindingDigest || p.ControlsDigest != NativeHostControlsDigest(s) || q.ProfileID != s.Profile.ProfileID || q.ProfileLockDigest != s.ProfileLockDigest {
		return nativeError()
	}
	if hostaction.Digest(p.Scope) != q.ScopeDigest || p.Scope.ProfileID != q.ProfileID || p.Scope.ProfileLockDigest != q.ProfileLockDigest || p.Scope.SourceCommit != q.SourceCommit || p.Scope.ExecutableDigest != q.ExecutableDigest || p.Observation.Binding.ScopeDigest != q.ScopeDigest || p.Observation.Binding.RecoveryEpoch != q.RecoveryEpoch || p.Observation.Binding.ControllerInstanceID != p.Scope.ControllerInstanceID || p.Observation.ExecutableDigest != q.ExecutableDigest || p.Observation.ChannelDigest != p.Scope.ConsoleReferenceDigest {
		return nativeError()
	}
	g, ok := nativeHostGuest(*p)
	if !ok {
		return nativeError()
	}
	d, err := nativeHostDiscovery(ctx, tx, s, g)
	if err != nil || d != p.DiscoveryDigest {
		return nativeError()
	}
	// Rejoin the exact own-host execution observed by the protected native
	// channel. A healthy unrelated guest or another lease is insufficient.
	b := p.Observation.Binding
	matches := 0
	for _, m := range s.Measurements {
		if m.Control.HostID == p.HostID && m.Receipt.Status == "succeeded" && m.Plan.PlanID == b.PlanID && m.Plan.PlanDigest == b.PlanDigest && m.Receipt.RunID == b.RunID && m.Receipt.StepID == b.StepID && m.Receipt.LeaseID == b.LeaseID && m.Receipt.RecoveryEpoch == q.RecoveryEpoch {
			matches++
		}
	}
	if matches == 0 {
		return nativeError()
	}
	return nil
}

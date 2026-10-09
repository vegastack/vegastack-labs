package gate

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/store"
	"strings"
	"testing"
	"time"
)

func cloneHostSnapshot(t *testing.T, s store.HostAdmissionSnapshot) store.HostAdmissionSnapshot {
	t.Helper()
	raw, e := json.Marshal(s)
	if e != nil {
		t.Fatal(e)
	}
	var copy store.HostAdmissionSnapshot
	if e = json.Unmarshal(raw, &copy); e != nil {
		t.Fatal(e)
	}
	return copy
}
func TestHostAdmissionInvalidationAndNoOlderFallback(t *testing.T) {
	at := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)
	full := qualifiedHostSnapshot(t, at)
	scope := hostScope("vegastack-labs")
	scope.StateRevision = 100
	cases := map[string]func(*store.HostAdmissionSnapshot){
		"identity":      func(s *store.HostAdmissionSnapshot) { s.IdentityDigest = "sha256:" + strings.Repeat("b", 64) },
		"epoch":         func(s *store.HostAdmissionSnapshot) { s.Revision.RecoveryEpoch++ },
		"profile-lock":  func(s *store.HostAdmissionSnapshot) { s.ProfileLock.ExecutableVersion = "2.0.0" },
		"qualification": func(s *store.HostAdmissionSnapshot) { s.Qualifications = nil },
		"qualification-source": func(s *store.HostAdmissionSnapshot) {
			s.Qualifications[0].SourceDigest = "sha256:" + strings.Repeat("b", 64)
		},
		"physical-from-virtual": func(s *store.HostAdmissionSnapshot) { s.Host.IdentityClass = "physical" },
		"prerequisite":          func(s *store.HostAdmissionSnapshot) { delete(s.PrerequisiteEvidenceIDs, "recovery-access") },
		"receipt": func(s *store.HostAdmissionSnapshot) {
			s.Measurements[0].Receipt.ResultDigest = "sha256:" + strings.Repeat("b", 64)
		},
		"missing-denial-probe": func(s *store.HostAdmissionSnapshot) {
			for i, c := range s.Results {
				if c.ControlID == "probe-source" {
					s.Results = append(s.Results[:i], s.Results[i+1:]...)
					break
				}
			}
		},
		"newest-revoked": func(s *store.HostAdmissionSnapshot) {
			e := s.Evidence[len(s.Evidence)-1]
			e.EvidenceID = "new-revoked"
			e.StateRevision = 99
			e.Status = "revoked"
			s.Evidence = append(s.Evidence, e)
		},
		"applied-binding": func(s *store.HostAdmissionSnapshot) { delete(s.AppliedBindings, "baseline-final") },
		"future-control": func(s *store.HostAdmissionSnapshot) {
			s.Results[0].ObservedAt = at.Add(time.Minute).Format(time.RFC3339)
			s.Measurements[0].Control = s.Results[0]
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			s := cloneHostSnapshot(t, full)
			change(&s)
			got, e := EvaluateHostAdmission(context.Background(), s, scope, "host.hardening-baseline", at)
			if e != nil || got.Outcome == "passed" {
				t.Fatal("mutation did not block", got, e)
			}
			if !strings.HasPrefix(got.ReasonCode, "host-") {
				t.Fatal("unsafe or vague host diagnostic", got.ReasonCode)
			}
		})
	}
}
func TestHostAdmissionUnrelatedRevisionAndImmediateAge(t *testing.T) {
	at := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)
	s := qualifiedHostSnapshot(t, at)
	scope := hostScope("vegastack-labs")
	scope.StateRevision = 50
	s.Revision.StateRevision = 101
	got, e := EvaluateHostAdmission(context.Background(), s, scope, "host.hardening-baseline", at)
	if e != nil || got.Outcome != "passed" {
		t.Fatal("unrelated revision invalidated host", got, e)
	}
	// Age only the actual control: qualification and prerequisite timestamps remain current.
	for i := range s.Measurements {
		if s.Measurements[i].Control.ControlID == "linux.audit-bounded" {
			x := &s.Measurements[i]
			x.Measurement.ObservedAt = at.Add(-24*time.Hour - time.Second).Format(time.RFC3339)
			x.Control.ObservedAt = x.Measurement.ObservedAt
			resealHostMeasurement(&s, x)
			s.Results[i] = x.Control
		}
	}
	got, e = EvaluateHostAdmission(context.Background(), s, scope, "host.hardening-baseline", at)
	if e != nil || got.ReasonCode != "host-control-stale:linux.auditd-bounded" {
		t.Fatal("control max age not isolated", got, e)
	}

}
func TestHostAdmissionReportsExactMissingControl(t *testing.T) {
	at := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)
	s := qualifiedHostSnapshot(t, at)
	for i, c := range s.Results {
		if c.ControlID == "linux.audit-bounded" {
			s.Results = append(s.Results[:i], s.Results[i+1:]...)
			break
		}
	}
	scope := hostScope("vegastack-labs")
	scope.StateRevision = 100
	got, e := EvaluateHostAdmission(context.Background(), s, scope, "host.hardening-baseline", at)
	if e != nil || got.ReasonCode != "host-control-missing:linux.auditd-bounded" {
		t.Fatal(got, e)
	}
	raw, _ := json.Marshal(got)
	if e = generated.ValidateContractJSON(generated.SchemaIDGateEvaluation, raw, generated.ContractExact); e != nil {
		t.Fatal(e)
	}
}

func TestHostReadOnlyRecollectionReusesOnlyExactCurrentProbeSequence(t *testing.T) {
	at := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)
	s := qualifiedHostSnapshot(t, at)
	for i := range s.Measurements {
		x := &s.Measurements[i]
		if x.Control.ControlID != "debian.accounts" {
			continue
		}
		request := x.Plan.HostAccessSequence.Actions[1]
		op := x.Plan.Operations[1]
		x.Plan.HostAccessSequence = nil
		x.Plan.HostAction = &request
		x.Plan.Operations = []generated.PlanOperation{op}
		x.Plan.PlanID = "read-only-recollect"
		x.Plan.PlanDigest = hostaction.Digest("read-only-recollect")
		x.Receipt.PlanID = x.Plan.PlanID
		x.Receipt.PlanDigest = x.Plan.PlanDigest
		x.Receipt.RunID = "read-only-run"
		x.Control.ActionReceiptDigest = hostaction.Digest(x.Receipt)
		s.Results[i] = x.Control
		s.ActionReceiptDigests = append(s.ActionReceiptDigests, x.Control.ActionReceiptDigest)
	}
	scope := hostScope("vegastack-labs")
	scope.StateRevision = 100
	got, e := EvaluateHostAdmission(context.Background(), s, scope, "host.hardening-baseline", at)
	if e != nil || got.Outcome != "passed" {
		t.Fatal(got, e)
	}
	for i := range s.Measurements {
		if s.Measurements[i].Control.ControlID == "debian.accounts" {
			s.Measurements[i].Plan.HostAction.ActionInputDigest = hostaction.Digest("changed")
		}
	}
	got, e = EvaluateHostAdmission(context.Background(), s, scope, "host.hardening-baseline", at)
	if e != nil || got.Outcome == "passed" {
		t.Fatal("changed recollection inherited old probes", got, e)
	}
}

func TestHostNewestNativeOutcomeSuppressesOldPositive(t *testing.T) {
	at := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)
	scope := hostScope("vegastack-labs")
	scope.StateRevision = 100
	for _, status := range []string{"failed", "partial", "revoked"} {
		t.Run(status, func(t *testing.T) {
			s := qualifiedHostSnapshot(t, at)
			b := s.Bundles["native-baseline"]
			b.Checks = append([]generated.GateEvidenceCheck{}, b.Checks...)
			if status != "revoked" {
				b.Checks[0].Result = status
			}
			hostTestEvidence(&s, "native-new-"+status, "native.baseline", b, at)
			if status == "revoked" {
				s.Evidence[len(s.Evidence)-1].Status = "revoked"
			}
			got, e := EvaluateHostAdmission(context.Background(), s, scope, "host.hardening-baseline", at)
			if e != nil || got.ReasonCode != "host-qualification-missing:baseline" {
				t.Fatal(got, e)
			}
		})
	}
}
func TestHostNewestExpiredProofHasIntactProvenance(t *testing.T) {
	at := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)
	s := qualifiedHostSnapshot(t, at)
	hostTestEvidence(&s, "baseline-expired", "host.hardening-baseline", s.Bundles["baseline-final"], at)
	s.Evidence[len(s.Evidence)-1].ExpiresAt = at.Add(time.Second).Format(time.RFC3339)
	scope := hostScope("vegastack-labs")
	scope.StateRevision = 100
	got, e := EvaluateHostAdmission(context.Background(), s, scope, "host.hardening-baseline", at.Add(time.Second))
	if e != nil || got.ReasonCode != "host-evidence-stale" {
		t.Fatal(got, e)
	}
}

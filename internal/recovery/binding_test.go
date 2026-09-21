package recovery

import (
	"math"
	"testing"
)

func TestValidateRunBindingRejectsStaleAndSubstitutedAuthority(t *testing.T) {
	plan := RestorePlanBinding{PlanID: "plan-a", PlanDigest: testDigest("a"), PointID: "point-a", PointDigest: testDigest("b"), ManifestDigest: testDigest("c"), VerificationDigest: testDigest("d"), FenceSetDigest: testDigest("e"), AuditDecisionDigest: testDigest("f"), CandidateDigest: testDigest("1"), TargetDigest: testDigest("2"), PriorInstanceID: "instance-old", NewInstanceID: "instance-new", StateRevision: 6, PriorRecoveryEpoch: 4, NextRecoveryEpoch: 5}
	run := RestoreRunIntent{RestorePlanBinding: plan, HumanAcknowledgementID: "ack-a"}
	live := AuthorityRevision{StateRevision: 6, RecoveryEpoch: 4, InstanceID: "instance-old"}
	if err := ValidateRunBinding(plan, run, live); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*RestorePlanBinding, *RestoreRunIntent, *AuthorityRevision){
		"stale epoch":             func(p *RestorePlanBinding, r *RestoreRunIntent, l *AuthorityRevision) { l.RecoveryEpoch++ },
		"stale revision":          func(p *RestorePlanBinding, r *RestoreRunIntent, l *AuthorityRevision) { l.StateRevision++ },
		"former instance changed": func(p *RestorePlanBinding, r *RestoreRunIntent, l *AuthorityRevision) { l.InstanceID = "other" },
		"source substituted": func(p *RestorePlanBinding, r *RestoreRunIntent, l *AuthorityRevision) {
			r.PointDigest = testDigest("3")
		},
		"fence substituted": func(p *RestorePlanBinding, r *RestoreRunIntent, l *AuthorityRevision) {
			r.FenceSetDigest = testDigest("3")
		},
		"audit substituted": func(p *RestorePlanBinding, r *RestoreRunIntent, l *AuthorityRevision) {
			r.AuditDecisionDigest = testDigest("3")
		},
		"candidate substituted": func(p *RestorePlanBinding, r *RestoreRunIntent, l *AuthorityRevision) {
			r.CandidateDigest = testDigest("3")
		},
		"target substituted": func(p *RestorePlanBinding, r *RestoreRunIntent, l *AuthorityRevision) {
			r.TargetDigest = testDigest("3")
		},
		"missing human": func(p *RestorePlanBinding, r *RestoreRunIntent, l *AuthorityRevision) { r.HumanAcknowledgementID = "" },
		"nonadjacent epoch": func(p *RestorePlanBinding, r *RestoreRunIntent, l *AuthorityRevision) {
			r.NextRecoveryEpoch += 1
			p.NextRecoveryEpoch += 1
		},
		"epoch overflow": func(p *RestorePlanBinding, r *RestoreRunIntent, l *AuthorityRevision) {
			p.PriorRecoveryEpoch, p.NextRecoveryEpoch = math.MaxInt64, math.MinInt64
			r.PriorRecoveryEpoch, r.NextRecoveryEpoch = math.MaxInt64, math.MinInt64
			l.RecoveryEpoch = math.MaxInt64
		},
	} {
		t.Run(name, func(t *testing.T) {
			p, r, l := plan, run, live
			mutate(&p, &r, &l)
			if ValidateRunBinding(p, r, l) == nil {
				t.Fatal("unsafe run accepted")
			}
		})
	}
}

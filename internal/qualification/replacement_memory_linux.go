//go:build linux

package qualification

import (
	"strconv"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

type nativeReplacementMemory struct {
	state   *generated.HostReplacementState
	witness *generated.NativeReplacementRecoveryWitness
	restart *generated.NativeReplacementRecoveryAttempt
}

func (d *ownedGuestLifecycle) captureReplacementOutput(in generated.NativeStepRequest, out generated.NativeStepResult) error {
	if in.ScenarioID != "replacement-recovery" {
		return nil
	}
	if hostaction.Digest(in) != hostaction.Digest(out.Binding) || out.Status != "completed" {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.replacement == nil {
		d.replacement = &nativeReplacementMemory{}
	}
	m := d.replacement
	if out.Preparation != nil && out.Preparation.ReplacementState != nil {
		s := *out.Preparation.ReplacementState
		if s.RestorationClass != "control-database" || s.FreezeEventDigest == "" || (s.Status != "frozen" && s.Status != "committed") {
			return ErrUnavailable
		}
		if m.witness != nil && (m.witness.ReplacementID != s.ReplacementID || m.witness.BindingDigest != s.BindingDigest) {
			return ErrUnavailable
		}
		if m.restart != nil && m.restart.Kind == "interrupted-transition" {
			if !sameReplacementOwnership(m.restart.Before, s) || !actualRecoveryRestart(*m.restart) {
				return ErrUnavailable
			}
			m.restart.After = s
			m.restart.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
			if appendReplacementAttempt(m, *m.restart) != nil {
				return ErrUnavailable
			}
			m.restart = nil
		}
		m.state = &s
	}
	if out.ReplacementRecovery != nil {
		w := out.ReplacementRecovery
		if len(w.Attempts) != 1 || w.Attempts[0].Kind == "interrupted-transition" {
			return ErrUnavailable
		}
		a := w.Attempts[0]
		if a.Before.ReplacementID != w.ReplacementID || a.Before.BindingDigest != w.BindingDigest || !sameReplacementOwnership(a.Before, a.After) {
			return ErrUnavailable
		}
		if a.Kind == "old-host-return" {
			if m.restart == nil || m.restart.Kind != "old-host-return" || !sameReplacementOwnership(m.restart.Before, a.Before) || !actualRecoveryRestart(*m.restart) {
				return ErrUnavailable
			}
			a.BeforeBootID, a.AfterBootID = m.restart.BeforeBootID, m.restart.AfterBootID
			a.BeforePID, a.AfterPID = m.restart.BeforePID, m.restart.AfterPID
			a.BeforeStartIdentity, a.AfterStartIdentity = m.restart.BeforeStartIdentity, m.restart.AfterStartIdentity
			m.restart = nil
		}
		if appendReplacementAttempt(m, a) != nil {
			return ErrUnavailable
		}
		state := a.After
		m.state = &state
	}
	return nil
}
func appendReplacementAttempt(m *nativeReplacementMemory, a generated.NativeReplacementRecoveryAttempt) error {
	if m.witness == nil {
		m.witness = &generated.NativeReplacementRecoveryWitness{Schema: generated.SchemaIDNativeReplacementRecoveryWitness, SchemaVersion: "1.0.0", ReplacementID: a.Before.ReplacementID, BindingDigest: a.Before.BindingDigest, Attempts: []generated.NativeReplacementRecoveryAttempt{}}
	}
	if m.witness.ReplacementID != a.Before.ReplacementID || m.witness.BindingDigest != a.Before.BindingDigest || len(m.witness.Attempts) >= 3 {
		return ErrUnavailable
	}
	for _, existing := range m.witness.Attempts {
		if existing.Kind == a.Kind {
			return ErrUnavailable
		}
	}
	m.witness.Attempts = append(m.witness.Attempts, a)
	return nil
}
func (d *ownedGuestLifecycle) beginReplacementRestart(in generated.NativeStepRequest, before string) error {
	if in.ScenarioID != "replacement-recovery" {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.replacement == nil || d.replacement.state == nil || d.replacement.restart != nil {
		return ErrUnavailable
	}
	s := d.replacement.state
	g := d.scope.guests[in.GuestID]
	kind := ""
	if s.Status == "frozen" && g.HostID == s.NewHostID && g.HostIdentityDigest == s.NewIdentityDigest && d.activeController == in.GuestID && d.recoveredController != nil {
		kind = "interrupted-transition"
	}
	if s.Status == "committed" && g.HostID == s.OldHostID && g.HostIdentityDigest == s.OldIdentityDigest && d.activeController != in.GuestID && d.recoveredController != nil {
		kind = "old-host-return"
	}
	if kind == "" {
		return ErrUnavailable
	}
	l := d.launches[in.GuestID]
	d.replacement.restart = &generated.NativeReplacementRecoveryAttempt{Schema: generated.SchemaIDNativeReplacementRecoveryAttempt, SchemaVersion: "1.0.0", Kind: kind, Before: *s, BeforeBootID: before, BeforePID: l.QEMUPID, BeforeStartIdentity: strconv.FormatInt(l.QEMUStartTimeTicks, 10)}
	return nil
}
func (d *ownedGuestLifecycle) finishReplacementRestart(in generated.NativeStepRequest, after string) error {
	if in.ScenarioID != "replacement-recovery" {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.replacement == nil || d.replacement.restart == nil {
		return ErrUnavailable
	}
	a := d.replacement.restart
	l := d.launches[in.GuestID]
	a.AfterBootID = after
	a.AfterPID = l.QEMUPID
	a.AfterStartIdentity = strconv.FormatInt(l.QEMUStartTimeTicks, 10)
	if !actualRecoveryRestart(*a) {
		return ErrUnavailable
	}
	return nil
}

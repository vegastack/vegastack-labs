package qualification

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/vegastack/vegastack-labs/internal/debianaccess"
	"github.com/vegastack/vegastack-labs/internal/debianbaseline"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

func validateBaselineScenarioEvidence(scenario string, executions []ProducerExecution, observations []generated.NativeObservation) error {
	if len(executions) == 0 || len(executions) != len(observations) {
		return ErrUnavailable
	}
	if scenario == "baseline-controls" {
		return validateNativeBaselineControls(executions)
	}
	if scenario != "baseline-access" && scenario != "access-idempotence" && scenario != "container-network" {
		return ErrUnavailable
	}
	groups := map[string][]ProducerExecution{}
	for _, e := range executions {
		groups[e.Reference.RunID] = append(groups[e.Reference.RunID], e)
	}
	count := 1
	if scenario == "access-idempotence" {
		count = 2
	}
	if len(groups) != count {
		return ErrUnavailable
	}
	type checked struct {
		input generated.DebianAccessInput
		apply ProducerExecution
		at    time.Time
	}
	var runs []checked
	for _, es := range groups {
		in, apply, err := validateNativeAccessSequence(es, scenario == "container-network")
		if err != nil {
			return err
		}
		at, err := time.Parse(time.RFC3339, apply.Result.ControlMeasurements[0].ObservedAt)
		if err != nil {
			return ErrUnavailable
		}
		runs = append(runs, checked{in, apply, at})
	}
	if count == 2 {
		sort.Slice(runs, func(i, j int) bool { return runs[i].at.Before(runs[j].at) })
		a, b := runs[0], runs[1]
		if !a.at.Before(b.at) || a.input.HostID != b.input.HostID || a.input.HostIdentityDigest != b.input.HostIdentityDigest || a.input.ProfileLockDigest != b.input.ProfileLockDigest || a.input.RenderedAccessDigest != b.input.RenderedAccessDigest || b.apply.Result.Changed {
			return ErrUnavailable
		}
	}
	return nil
}

func validateNativeBaselineControls(es []ProducerExecution) error {
	required := map[string]bool{"linux.fail2ban-sshd": false, "linux.audit-bounded": false, "linux.apparmor-enforcing": false, "linux.aide-integrity": false, "linux.update-health": false, "linux.time-sync": false, "linux.resource-health": false, "linux.kernel-settings": false}
	var host, identity, lock string
	for _, e := range es {
		r, err := producerAction(e)
		if err != nil || r.ActionID != "debian.baseline.collect" {
			return ErrUnavailable
		}
		in, err := debianbaseline.DecodeInput([]byte(r.ActionInput))
		if err != nil {
			return ErrUnavailable
		}
		if host == "" {
			host, identity, lock = in.HostID, in.HostIdentityDigest, in.ProfileLockDigest
		} else if host != in.HostID || identity != in.HostIdentityDigest || lock != in.ProfileLockDigest {
			return ErrUnavailable
		}
		if len(e.Result.ControlMeasurements) != len(in.ControlIDs) {
			return ErrUnavailable
		}
		seen := map[string]bool{}
		for _, m := range e.Result.ControlMeasurements {
			declared := false
			for _, id := range in.ControlIDs {
				declared = declared || id == m.ControlID
			}
			prior, known := required[m.ControlID]
			if !declared || !known || prior || seen[m.ControlID] || m.Status != "passed" || m.Kind != "baseline" || m.ProducerID != "debian-baseline" || m.ProducerVersion != "1.0.0" || m.SubjectHostID != host || m.SubjectIdentityDigest != identity || m.ProfileLockDigest != lock || m.ConfigurationDigest != hostaction.Digest(in) || m.MeasurementDigest != hostaction.MeasurementDigest(m) || m.Baseline == nil || m.Baseline.Verification != "configuration-observed" || m.Baseline.FactsDigest == "" {
				return ErrUnavailable
			}
			if m.ControlID == "linux.aide-integrity" && in.AIDE.ReferenceDigest == "" {
				return ErrUnavailable
			}
			seen[m.ControlID], required[m.ControlID] = true, true
		}
	}
	for _, found := range required {
		if !found {
			return ErrUnavailable
		}
	}
	return nil
}

// Rebuild the owning sequence and require every measured operation from its
// single actual run. A confirm receipt alone cannot stand in for its probes.
func validateNativeAccessSequence(es []ProducerExecution, containers bool) (generated.DebianAccessInput, ProducerExecution, error) {
	var zero generated.DebianAccessInput
	var no ProducerExecution
	if len(es) == 0 || es[0].Plan.HostAccessSequence == nil {
		return zero, no, ErrUnavailable
	}
	p := es[0].Plan
	s := p.HostAccessSequence
	rebuilt, err := debianaccess.Sequence(p.Operations, s.Actions)
	if err != nil || hostaction.Digest(rebuilt) != hostaction.Digest(*s) || len(es) != len(s.Actions) {
		return zero, no, ErrUnavailable
	}
	in, err := debianaccess.DecodeInput([]byte(s.Actions[0].ActionInput))
	if err != nil || containers && len(in.ContainerFlows) == 0 {
		return zero, no, ErrUnavailable
	}
	byOp := map[string]ProducerExecution{}
	for _, e := range es {
		if e.Reference.RunID != es[0].Reference.RunID || e.Plan.PlanDigest != p.PlanDigest || byOp[e.Receipt.OperationID].Result != nil {
			return zero, no, ErrUnavailable
		}
		if _, err := producerAction(e); err != nil {
			return zero, no, err
		}
		byOp[e.Receipt.OperationID] = e
	}
	digests := []string{}
	record := ""
	var apply ProducerExecution
	for i, op := range p.Operations {
		e, ok := byOp[op.OperationID]
		if !ok {
			return zero, no, ErrUnavailable
		}
		r := s.Actions[i]
		ms := e.Result.ControlMeasurements
		if len(ms) == 0 {
			return zero, no, ErrUnavailable
		}
		switch r.ActionID {
		case "debian.access.apply", "debian.access.collect":
			if validateNativeAccessConfiguration(in, ms, containers) != nil {
				return zero, no, ErrUnavailable
			}
			if i == 0 {
				apply = e
				for _, m := range ms {
					if m.RollbackRecordDigest != "" {
						if record != "" && record != m.RollbackRecordDigest {
							return zero, no, ErrUnavailable
						}
						record = m.RollbackRecordDigest
					}
				}
			}
		case "debian.access.probe.local", "debian.access.probe-source":
			var probe generated.AccessProbeInput
			if json.Unmarshal([]byte(r.ActionInput), &probe) != nil || validateNativeProbeMeasurements(probe, ms) != nil {
				return zero, no, ErrUnavailable
			}
		case "debian.access.confirm":
			if len(ms) != 1 || record == "" || ms[0].Status != "passed" || ms[0].ProducerID != "debian-access-native" || ms[0].Reason != "independent-probes-confirmed" || ms[0].PositiveProbeDigest != hostaction.Digest(digests) || ms[0].NegativeProbeDigest != hostaction.Digest(digests) || ms[0].RollbackRecordDigest != record {
				return zero, no, ErrUnavailable
			}
		default:
			return zero, no, ErrUnavailable
		}
		if r.ActionID != "debian.access.confirm" {
			for _, m := range ms {
				digests = append(digests, hostaction.Digest([]string{op.OperationID, m.MeasurementDigest, hostaction.Digest(e.Receipt), e.Result.ResultDigest}))
			}
		}
	}
	return in, apply, nil
}

func validateNativeAccessConfiguration(in generated.DebianAccessInput, ms []generated.AccessMeasurement, containers bool) error {
	want := map[string]string{"debian.accounts": "account", "debian.ssh": "ssh", "debian.host-firewall": "host-flow", "debian.container-firewall": "container-flow"}
	if len(ms) != len(want) {
		return ErrUnavailable
	}
	for _, m := range ms {
		kind, ok := want[m.ControlID]
		if !ok || kind != m.Kind || m.ProducerID != "debian-access-native" || m.ProducerVersion != "1.0.0" || m.SubjectHostID != in.HostID || m.SubjectIdentityDigest != in.HostIdentityDigest || m.ProfileLockDigest != in.ProfileLockDigest || m.ConfigurationDigest != in.RenderedAccessDigest || m.MeasurementDigest != hostaction.MeasurementDigest(m) {
			return ErrUnavailable
		}
		absent := !containers && len(in.ContainerFlows) == 0 && m.ControlID == "debian.container-firewall" && m.Status == "partial" && m.Reason == "container-not-installed"
		if m.Status != "passed" && !absent {
			return ErrUnavailable
		}
		delete(want, m.ControlID)
	}
	return nil
}

func validateNativeProbeMeasurements(in generated.AccessProbeInput, ms []generated.AccessMeasurement) error {
	if len(ms) != len(in.Cases) {
		return ErrUnavailable
	}
	seen := map[string]bool{}
	for _, m := range ms {
		var c *generated.AccessProbeCase
		for i := range in.Cases {
			if in.Cases[i].ProbeID == m.ControlID {
				c = &in.Cases[i]
			}
		}
		p := m.Probe
		if c == nil || seen[m.ControlID] || p == nil || m.Status != "passed" || m.ProducerID != "debian-access-probe" || m.ProducerVersion != "1.0.0" || m.SubjectHostID != in.SubjectHostID || m.SubjectIdentityDigest != in.SubjectIdentityDigest || m.ProfileLockDigest != in.ProfileLockDigest || m.ConfigurationDigest != in.ApplyInputDigest || m.MeasurementDigest != hostaction.MeasurementDigest(m) || p.ProbeID != c.ProbeID || p.Expected != c.Expected || p.Actual != c.Expected || p.DestinationDigest != hostaction.Digest(c.Destination) || p.SourceHostID != in.Source.HostID || p.SourceIdentityDigest != in.Source.IdentityDigest || p.SourceContextDigest != in.Source.ContextDigest || p.ActualSourceAddress != in.Source.Address || p.ActualSourceAddress == "" || p.ActualSourceAddress == "unavailable" || p.WitnessDigest == "" || p.SourceNamespaceDigest == "" || p.WitnessDigest == hostaction.Digest(nil) || p.SourceNamespaceDigest == hostaction.Digest(nil) {
			return ErrUnavailable
		}
		if c.Expected == "allowed" && m.PositiveProbeDigest != hostaction.Digest(*p) || c.Expected == "denied" && m.NegativeProbeDigest != hostaction.Digest(*p) {
			return ErrUnavailable
		}
		seen[m.ControlID] = true
	}
	return nil
}

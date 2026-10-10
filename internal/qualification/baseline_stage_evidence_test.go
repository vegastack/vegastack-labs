package qualification

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"testing"
)

func TestNativeAccessConfigurationKeepsContainerAbsencePartial(t *testing.T) {
	d := hostaction.Digest("configuration")
	in := generated.DebianAccessInput{HostID: "subject", HostIdentityDigest: d, ProfileLockDigest: d, RenderedAccessDigest: d}
	var ms []generated.AccessMeasurement
	for id, kind := range map[string]string{"debian.accounts": "account", "debian.ssh": "ssh", "debian.host-firewall": "host-flow", "debian.container-firewall": "container-flow"} {
		m := generated.AccessMeasurement{ControlID: id, Kind: kind, Status: "passed", ProducerID: "debian-access-native", ProducerVersion: "1.0.0", SubjectHostID: in.HostID, SubjectIdentityDigest: d, ProfileLockDigest: d, ConfigurationDigest: d}
		if id == "debian.container-firewall" {
			m.Status = "partial"
			m.Reason = "container-not-installed"
		}
		m.MeasurementDigest = hostaction.MeasurementDigest(m)
		ms = append(ms, m)
	}
	if err := validateNativeAccessConfiguration(in, ms, false); err != nil {
		t.Fatal(err)
	}
	if err := validateNativeAccessConfiguration(in, ms, true); err == nil {
		t.Fatal("container-native accepted absence")
	}
	for i := range ms {
		if ms[i].ControlID == "debian.container-firewall" {
			ms[i].Status = "passed"
			ms[i].Reason = "measured"
			ms[i].MeasurementDigest = hostaction.MeasurementDigest(ms[i])
		}
	}
	if err := validateNativeAccessConfiguration(in, ms, true); err != nil {
		t.Fatal(err)
	}
	ms[0].SubjectHostID = "substituted"
	ms[0].MeasurementDigest = hostaction.MeasurementDigest(ms[0])
	if err := validateNativeAccessConfiguration(in, ms, true); err == nil {
		t.Fatal("accepted another host's observations")
	}
}

func TestNativeProbeEvidenceRequiresExactMeasuredDenial(t *testing.T) {
	d := hostaction.Digest("test")
	in := generated.AccessProbeInput{SubjectHostID: "subject", SubjectIdentityDigest: d, ProfileLockDigest: d, ApplyInputDigest: d, Source: generated.AccessProbeSource{HostID: "source", IdentityDigest: d, ContextDigest: d, Address: "192.0.2.11"}, Cases: []generated.AccessProbeCase{{ProbeID: "denied-port", Kind: "host-flow", Expected: "denied", Destination: generated.AccessProbeTuple{Address: "192.0.2.10", Port: 22}}}}
	p := generated.AccessProbeObservation{ProbeID: "denied-port", SourceHostID: "source", SourceIdentityDigest: d, SourceContextDigest: d, ActualSourceAddress: "192.0.2.11", SourceNamespaceDigest: d, DestinationDigest: hostaction.Digest(in.Cases[0].Destination), WitnessDigest: d, Expected: "denied", Actual: "denied"}
	m := generated.AccessMeasurement{ControlID: p.ProbeID, Status: "passed", ProducerID: "debian-access-probe", ProducerVersion: "1.0.0", SubjectHostID: in.SubjectHostID, SubjectIdentityDigest: d, ProfileLockDigest: d, BundleDigest: hostaction.Digest(in), ConfigurationDigest: d, Probe: &p, NegativeProbeDigest: hostaction.Digest(p)}
	m.MeasurementDigest = hostaction.MeasurementDigest(m)
	if err := validateNativeProbeMeasurements(in, []generated.AccessMeasurement{m}); err != nil {
		t.Fatal(err)
	}
	for _, variant := range []string{"destination", "outcome", "witness", "source"} {
		t.Run(variant, func(t *testing.T) {
			changed := m
			probe := p
			changed.Probe = &probe
			switch variant {
			case "destination":
				probe.DestinationDigest = hostaction.Digest("wrong")
			case "outcome":
				probe.Actual = "error"
			case "witness":
				probe.WitnessDigest = hostaction.Digest(nil)
			case "source":
				probe.SourceHostID = "other"
			}
			changed.NegativeProbeDigest = hostaction.Digest(probe)
			changed.MeasurementDigest = hostaction.MeasurementDigest(changed)
			if validateNativeProbeMeasurements(in, []generated.AccessMeasurement{changed}) == nil {
				t.Fatal("accepted substituted probe")
			}
		})
	}
	if validateNativeProbeMeasurements(in, nil) == nil {
		t.Fatal("accepted missing probe")
	}
}

func TestNativeBaselineScenarioRejectsReceiptPresenceOnly(t *testing.T) {
	for _, scenario := range []string{"baseline-access", "baseline-controls", "access-idempotence", "container-network"} {
		t.Run(scenario, func(t *testing.T) {
			if validateBaselineScenarioEvidence(scenario, []ProducerExecution{{Receipt: generated.ExecutionReceipt{Status: "succeeded"}}}, []generated.NativeObservation{{ProcessState: "running", ConsoleState: "healthy"}}) == nil {
				t.Fatal("receipt and healthy VM qualified")
			}
		})
	}
}

package debianaccess

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

var errProbe = errors.New("access probe unavailable")

type SourceIdentity struct{ NamespaceDigest, RouteDigest string }

// WithSource remeasures a prepared exact context and runs fn inside it. It must
// reject changed identity, address, interface or route before any probe socket.
type SourceContextResolver interface {
	WithSource(context.Context, generated.AccessProbeSource, []generated.AccessProbeTuple, func(SourceIdentity) error) error
}
type LocalProbeRuntime struct{ Sources SourceContextResolver }
type LocalProbe struct{ runtime LocalProbeRuntime }

func NewLocalProbe(r LocalProbeRuntime) LocalProbe { return LocalProbe{runtime: r} }
func (p LocalProbe) Execute(ctx context.Context, input generated.AccessProbeInput, values []*credentialref.Value) ([]generated.AccessMeasurement, error) {
	if input.Source.Kind != "host-network" {
		return nil, errProbe
	}
	var key []byte
	for _, c := range input.Cases {
		if c.Kind == "ssh-admin" {
			if len(values) != 1 || values[0] == nil {
				return nil, errProbe
			}
			key = values[0].Bytes()
		}
	}
	return executeProbes(ctx, input, p.runtime.Sources, key, false)
}
func ExecuteSourceProbe(ctx context.Context, input generated.AccessProbeInput, resolver SourceContextResolver) ([]generated.AccessMeasurement, error) {
	return executeProbes(ctx, input, resolver, nil, true)
}
func executeProbes(ctx context.Context, input generated.AccessProbeInput, resolver SourceContextResolver, key []byte, remote bool) ([]generated.AccessMeasurement, error) {
	raw, err := json.Marshal(input)
	if ProtectedName(input.SubjectHostID) || ProtectedName(input.Source.HostID) || ctx == nil || ctx.Err() != nil || resolver == nil || err != nil || len(raw) > 32768 || generated.ValidateContractJSON(generated.SchemaIDAccessProbeInput, raw, generated.ContractExact) != nil || len(input.Cases) == 0 || len(input.Cases) > 8 {
		return nil, errProbe
	}
	source, err := netip.ParseAddr(input.Source.Address)
	if err != nil || source.IsUnspecified() || source.IsMulticast() {
		return nil, errProbe
	}
	if (source.Is4() && input.Source.Family != "ipv4") || (!source.Is4() && input.Source.Family != "ipv6") {
		return nil, errProbe
	}
	// Each case has witness-before, actual probe and witness-after. The complete
	// immutable step must fit its lease, including a two-second recording margin.
	budget, err := RequiredProbeDuration(input)
	if err != nil {
		return nil, err
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) < budget {
		return nil, errProbe
	}
	seen := map[string]bool{}
	for _, c := range input.Cases {
		if (strings.HasPrefix(c.Kind, "ssh-") && c.Destination.Protocol != "tcp") || seen[c.ProbeID] || ((c.Kind == "ssh-wrong-user" || c.Kind == "ssh-root" || c.Kind == "ssh-password") && c.Expected != "denied") || (remote && c.Kind == "ssh-admin") || c.Destination.HostID != input.SubjectHostID || c.Destination.IdentityDigest != input.SubjectIdentityDigest {
			return nil, errProbe
		}
		seen[c.ProbeID] = true
		for _, tuple := range []generated.AccessProbeTuple{c.Destination, c.Witness} {
			ip, e := netip.ParseAddr(tuple.Address)
			if ProtectedName(tuple.HostID) || e != nil || ip.Is4() != source.Is4() || ip.IsUnspecified() || ip.IsMulticast() || tuple.Port > 65535 {
				return nil, errProbe
			}
		}
	}
	measurements := make([]generated.AccessMeasurement, 0, len(input.Cases))
	for _, c := range input.Cases {
		var actual SocketObservation
		var identity SourceIdentity
		var witnessDigest string
		err := resolver.WithSource(ctx, input.Source, []generated.AccessProbeTuple{c.Destination, c.Witness}, func(id SourceIdentity) error {
			identity = id
			if id.RouteDigest != input.Source.RouteDigest || id.NamespaceDigest == "" {
				return errProbe
			}
			before := probeTuple(ctx, input, c.Witness, "tcp", "", nil)
			if before.Outcome != "allowed" {
				return errProbe
			}
			kind, user := "tcp", ""
			switch c.Kind {
			case "ssh-admin":
				kind, user = "ssh-key", input.AdministratorUser
			case "ssh-wrong-user":
				kind, user = "ssh-invalid-key", "vsk-invalid-probe-user"
			case "ssh-password":
				kind, user = "ssh-password", input.AdministratorUser
			case "ssh-root":
				kind, user = "ssh-invalid-key", "root"
			case "ssh-source":
				kind, user = "ssh-handshake", input.AdministratorUser
			}
			actual = probeTuple(ctx, input, c.Destination, kind, user, key)
			after := probeTuple(ctx, input, c.Witness, "tcp", "", nil)
			if after.Outcome != "allowed" || before.LocalIP != after.LocalIP || actual.LocalIP != before.LocalIP {
				return errProbe
			}
			witnessDigest = hostaction.Digest(struct {
				Tuple         generated.AccessProbeTuple
				Before, After SocketObservation
			}{c.Witness, before, after})
			return nil
		})
		if err != nil {
			actual.Outcome = "error"
		}
		status, reason := "failed", "unexpected-outcome"
		if actual.Outcome == "error" {
			status, reason = "error", "probe-unavailable"
		} else if actual.Outcome == c.Expected {
			status, reason = "passed", "measured"
		}
		kind := "host-flow"
		if strings.HasPrefix(c.Kind, "ssh-") {
			kind = "ssh"
		} else if strings.HasPrefix(c.Kind, "container-") {
			kind = "container-flow"
		}
		// Empty/failed identities have explicit digests, never a successful claim.
		if witnessDigest == "" {
			witnessDigest = hostaction.Digest(nil)
		}
		if identity.NamespaceDigest == "" {
			identity.NamespaceDigest = hostaction.Digest(nil)
		}
		observed := generated.AccessProbeObservation{Schema: generated.SchemaIDAccessProbeObservation, SchemaVersion: "1.0.0", ProbeID: c.ProbeID, SourceHostID: input.Source.HostID, SourceIdentityDigest: input.Source.IdentityDigest, SourceContextDigest: input.Source.ContextDigest, ActualSourceAddress: actual.LocalIP, SourceNamespaceDigest: identity.NamespaceDigest, DestinationDigest: hostaction.Digest(c.Destination), WitnessDigest: witnessDigest, Expected: c.Expected, Actual: actual.Outcome}
		if observed.ActualSourceAddress == "" {
			observed.ActualSourceAddress = "unavailable"
		}
		m := generated.AccessMeasurement{Schema: generated.SchemaIDAccessMeasurement, SchemaVersion: "1.0.0", ControlID: c.ProbeID, Kind: kind, Status: status, SubjectHostID: input.SubjectHostID, SubjectIdentityDigest: input.SubjectIdentityDigest, ProfileLockDigest: input.ProfileLockDigest, ProducerID: "debian-access-probe", ProducerVersion: "1.0.0", BundleDigest: hostaction.Digest(input), ObservedAt: time.Now().UTC().Format(time.RFC3339), ConfigurationDigest: input.ApplyInputDigest, PositiveProbeDigest: witnessDigest, NegativeProbeDigest: hostaction.Digest(nil), Reason: reason, Probe: &observed}
		if c.Expected == "denied" {
			m.NegativeProbeDigest = hostaction.Digest(observed)
		} else {
			m.PositiveProbeDigest = hostaction.Digest(observed)
		}
		m.MeasurementDigest = hostaction.MeasurementDigest(m)
		measurements = append(measurements, m)
	}
	return measurements, nil
}
func probeTuple(ctx context.Context, input generated.AccessProbeInput, tuple generated.AccessProbeTuple, kind, user string, key []byte) SocketObservation {
	if tuple.Protocol != "tcp" {
		return probeUDP(ctx, input, tuple)
	}
	var previous SocketObservation
	for attempt := int64(0); attempt < input.Attempts; attempt++ {
		observation := ProbeSocket(ctx, SocketProbe{Timeout: time.Duration(input.TimeoutMillis) * time.Millisecond, SourceIP: input.Source.Address, DestinationIP: tuple.Address, Port: uint16(tuple.Port), HostKey: input.SubjectHostKey, Kind: kind, User: user}, key)
		if attempt > 0 && (previous.Outcome != observation.Outcome || previous.LocalIP != observation.LocalIP) {
			return SocketObservation{Outcome: "error"}
		}
		previous = observation
	}
	return previous
}

// RequiredProbeDuration includes fresh witness-before/after, bounded namespace
// route/container inspection, and a recording margin. Plan construction uses
// the same bound before acknowledging or applying any access change.
func RequiredProbeDuration(input generated.AccessProbeInput) (time.Duration, error) {
	if len(input.Cases) < 1 || len(input.Cases) > 8 || input.Attempts < 1 || input.Attempts > 2 || input.TimeoutMillis < 1 || input.TimeoutMillis > 2000 {
		return 0, errProbe
	}
	return time.Duration(len(input.Cases)*3)*time.Duration(input.Attempts)*time.Duration(input.TimeoutMillis)*time.Millisecond + time.Duration(len(input.Cases))*5*time.Second + 2*time.Second, nil
}

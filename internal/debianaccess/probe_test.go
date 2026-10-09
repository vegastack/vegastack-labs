package debianaccess

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

type fixtureSource struct {
	fail  bool
	calls int
}

func (f *fixtureSource) WithSource(_ context.Context, s generated.AccessProbeSource, _ []generated.AccessProbeTuple, fn func(SourceIdentity) error) error {
	f.calls++
	if f.fail {
		return errProbe
	}
	return fn(SourceIdentity{NamespaceDigest: hostaction.Digest("fixture-namespace"), RouteDigest: s.RouteDigest})
}
func probeInput(t *testing.T, witnessPort, targetPort int) generated.AccessProbeInput {
	d := hostaction.Digest("synthetic-only")
	tuple := func(port int) generated.AccessProbeTuple {
		return generated.AccessProbeTuple{Schema: generated.SchemaIDAccessProbeTuple, SchemaVersion: "1.0.0", HostID: "test-subject", IdentityDigest: d, Address: "127.0.0.1", Port: int64(port), Protocol: "tcp"}
	}
	return generated.AccessProbeInput{Schema: generated.SchemaIDAccessProbeInput, SchemaVersion: "1.0.0", SubjectHostID: "test-subject", SubjectIdentityDigest: d, SubjectHostKey: "unused-tcp-only", ProfileLockDigest: d, ApplyInputDigest: d, RollbackDigest: d, AdministratorUser: "admin", Source: generated.AccessProbeSource{Schema: generated.SchemaIDAccessProbeSource, SchemaVersion: "1.0.0", HostID: "test-source", IdentityDigest: d, Kind: "host-network", ContextID: "test-context", ContextDigest: d, Interface: "lo", InterfaceIndex: 1, Address: "127.0.0.1", Family: "ipv4", RouteDigest: d}, Cases: []generated.AccessProbeCase{{Schema: generated.SchemaIDAccessProbeCase, SchemaVersion: "1.0.0", ProbeID: "denied-port", Kind: "host-flow", Expected: "denied", Destination: tuple(targetPort), Witness: tuple(witnessPort)}}, TimeoutMillis: 100, Attempts: 1}
}
func listenerPort(t *testing.T) (net.Listener, int) {
	t.Helper()
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	_, p, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(p)
	return ln, port
}
func TestAccessProbeDenialNeedsLiveWitnessAndCurrentSource(t *testing.T) {
	witness, wp := listenerPort(t)
	defer witness.Close()
	go func() {
		for {
			c, e := witness.Accept()
			if e != nil {
				return
			}
			c.Close()
		}
	}()
	closed, cp := listenerPort(t)
	closed.Close()
	input := probeInput(t, wp, cp)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	source := &fixtureSource{}
	measurements, e := ExecuteSourceProbe(ctx, input, source)
	if e != nil || len(measurements) != 1 || measurements[0].Status != "passed" {
		t.Fatalf("actual denied port with live witness: %+v %v", measurements, e)
	}
	witness.Close()
	measurements, e = ExecuteSourceProbe(ctx, input, source)
	if e != nil || measurements[0].Status != "error" {
		t.Fatalf("dead witness passed: %+v %v", measurements, e)
	}
	source.fail = true
	measurements, e = ExecuteSourceProbe(ctx, input, source)
	if e != nil || measurements[0].Status != "error" {
		t.Fatalf("changed source passed: %+v %v", measurements, e)
	}
}
func TestAccessProbeRejectsUnfittingLeaseAndRemoteAdministratorKey(t *testing.T) {
	input := probeInput(t, 1, 2)
	source := &fixtureSource{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if _, e := ExecuteSourceProbe(ctx, input, source); e == nil || source.calls != 0 {
		t.Fatal("unfitting lease reached source")
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Minute)
	defer cancel2()
	input.Cases[0].Kind = "ssh-admin"
	if _, e := ExecuteSourceProbe(ctx2, input, source); e == nil || source.calls != 0 {
		t.Fatal("remote administrator probe accepted")
	}
}

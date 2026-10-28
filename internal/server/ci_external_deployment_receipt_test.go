package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/adapter/serviceruntime"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestCIExternalReceiptHasNoCentralOrUnboundExecution(t *testing.T) {
	v := newCIExternalDeploymentReceipt(nil, nil)
	if _, e := v.Execute(context.Background(), adapter.Operation{}); e == nil {
		t.Fatal("central execute accepted")
	}
	if _, e := v.Verify(context.Background(), adapter.Operation{}, adapter.Effect{Status: "succeeded"}); e == nil {
		t.Fatal("caller effect accepted")
	}
	if got, e := v.(adapter.ReceiptVerifier).VerifyReceipt(context.Background(), adapter.Operation{}, adapter.ReceiptObservation{Status: "succeeded", ResultDigest: "sha256:" + strings.Repeat("a", 64)}); e == nil || got.Verified || got.Changed || got.Digest != "" {
		t.Fatalf("unbound receipt: %+v %v", got, e)
	}
}
func TestCIExternalReceiptRequiresIndependentHealthyExactImage(t *testing.T) {
	a := generated.ServiceDeploymentArtifact{Repository: "registry.example/app", Digest: "sha256:" + strings.Repeat("a", 64)}
	good := serviceruntime.Snapshot{RepoDigest: a.Repository + "@" + a.Digest, Running: true, Health: "healthy"}
	if !ciExternalRuntimeMatches(good, a) {
		t.Fatal("exact healthy running target rejected")
	}
	for _, fault := range []string{"stopped", "unhealthy", "unknown-health", "other-image"} {
		t.Run(fault, func(t *testing.T) {
			s := good
			switch fault {
			case "stopped":
				s.Running = false
			case "unhealthy":
				s.Health = "unhealthy"
			case "unknown-health":
				s.Health = "unknown"
			case "other-image":
				s.RepoDigest = a.Repository + "@sha256:" + strings.Repeat("b", 64)
			}
			if ciExternalRuntimeMatches(s, a) {
				t.Fatal("unproven target accepted")
			}
		})
	}
}
func TestCIExternalReceiptRechecksEachActualHTTPRequest(t *testing.T) {
	calls := 0
	peer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.Write([]byte(`{}`)) }))
	defer peer.Close()
	checks := 0
	revoked := errors.New("revoked")
	transport := ciReceiptTransport{next: peer.Client().Transport, check: func(context.Context) error {
		checks++
		if checks >= 3 {
			return revoked
		}
		return nil
	}}
	client := &http.Client{Transport: transport}
	first, e := client.Get(peer.URL)
	if e != nil {
		t.Fatal(e)
	}
	first.Body.Close()
	if _, e = client.Get(peer.URL); !errors.Is(e, revoked) {
		t.Fatalf("second request %v", e)
	}
	if calls != 1 || checks != 3 {
		t.Fatalf("provider calls=%d checks=%d", calls, checks)
	}
}

type ciReceiptReadObserver struct{ calls int }

func (o *ciReceiptReadObserver) Observe(ctx context.Context, _ serviceruntime.Target, _ serviceruntime.Selection, _ *credentialref.Value, check serviceruntime.Check) (serviceruntime.Snapshot, error) {
	o.calls++
	if e := check(ctx); e != nil {
		return serviceruntime.Snapshot{}, e
	}
	return serviceruntime.Snapshot{Running: true}, nil
}
func TestCIExternalReceiptRuntimeAuthorityCannotBeSkipped(t *testing.T) {
	observer := &ciReceiptReadObserver{}
	revoked := errors.New("revoked")
	checks := 0
	wrapper := ciReceiptRuntime{next: observer, check: func(context.Context) error {
		checks++
		if checks >= 2 {
			return revoked
		}
		return nil
	}}
	got, e := wrapper.Observe(context.Background(), serviceruntime.Target{}, serviceruntime.Selection{}, nil, func(context.Context) error { return nil })
	if !errors.Is(e, revoked) || got.Running || observer.calls != 1 {
		t.Fatalf("runtime authority %+v %v calls=%d", got, e, observer.calls)
	}
	if _, e = wrapper.ObserveCapacity(context.Background(), serviceruntime.Target{}, nil, func(context.Context) error { return nil }); e == nil {
		t.Fatal("missing capacity observer accepted")
	}
}

package server

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

func TestIngressPilotOriginRequiresRealTLSPinAndSignedOutDenial(t *testing.T) {
	certificatePath, keyPath := writeRemoteTestCertificate(t)
	certificate, err := tls.LoadX509KeyPair(certificatePath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	status := http.StatusUnauthorized
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "console.example" || r.URL.Path != "/api/v1/status" || r.Header.Get("Authorization") != "" || r.Header.Get("Cf-Access-Jwt-Assertion") != "" {
			t.Error("unexpected origin probe")
		}
		w.WriteHeader(status)
	}))
	origin.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13}
	origin.StartTLS()
	defer origin.Close()
	p := serverconfig.Profile{RemoteRead: serverconfig.RemoteRead{TLSCertificatePath: certificatePath, TLSPrivateKeyPath: keyPath}, IngressControllerReadPilot: &generated.IngressControllerReadPilot{Change: generated.IngressChange{Hostname: "console.example", OriginServerName: "console.example", OriginService: origin.URL, OriginIdentityDigest: digestBytes(certificate.Certificate[0])}}}
	if _, err := probePilotOrigin(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	status = http.StatusOK
	if _, err := probePilotOrigin(context.Background(), p); err == nil {
		t.Fatal("unauthenticated API success accepted")
	}
	status = http.StatusUnauthorized
	p.IngressControllerReadPilot.Change.OriginIdentityDigest = digestBytes([]byte("other-certificate"))
	if _, err := probePilotOrigin(context.Background(), p); err == nil {
		t.Fatal("wrong certificate pin accepted")
	}
	p.IngressControllerReadPilot.Change.OriginIdentityDigest = digestBytes(certificate.Certificate[0])
	p.IngressControllerReadPilot.Change.OriginServerName = "other.example"
	if _, err := probePilotOrigin(context.Background(), p); err == nil {
		t.Fatal("wrong TLS name accepted")
	}
}

func TestIngressPilotEvidenceNeverBecomesRemoteMutation(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		if api.RemoteReadRequestAllowed(method, "/api/v1/network/ingress/pilot-evidence") {
			t.Fatal("pilot collector exposed through remote browser boundary")
		}
	}
}

func TestControllerReadPilotListenerAllowsOnlyReadsAndExistingSessions(t *testing.T) {
	calls := 0
	handler := controllerReadPilotHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(http.StatusNoContent) }))
	for _, path := range []string{"/api/v1/plans/pilot/execute", "/api/v1/executor-leases/claim", "/api/v1/network/ingress/pilot-evidence", "/api/v1/host-adoptions/draft"} {
		before := calls
		r := httptest.NewRequest(http.MethodPost, path, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusNotFound || calls != before {
			t.Fatalf("pilot exposed mutation %s", path)
		}
	}
	for _, request := range []struct{ method, path string }{{http.MethodGet, "/api/v1/hosts"}, {http.MethodGet, "/"}, {http.MethodPost, "/api/v1/session"}, {http.MethodPost, "/api/v1/session/renew"}, {http.MethodPost, "/api/v1/session/logout"}} {
		r := httptest.NewRequest(request.method, request.path, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusNoContent {
			t.Fatalf("pilot blocked read/session %s", request.path)
		}
	}
}

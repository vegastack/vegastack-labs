package server

import (
	"context"
	"crypto/tls"
	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/generated"
	ingress "github.com/vegastack/vegastack-labs/internal/networkingress"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBootstrapOriginRequiresCurrentRealTLSAndSignedOutDenial(t *testing.T) {
	certPath, keyPath := writeRemoteTestCertificate(t)
	cert, e := tls.LoadX509KeyPair(certPath, keyPath)
	if e != nil {
		t.Fatal(e)
	}
	status := http.StatusForbidden
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cf-Access-Jwt-Assertion") != "" {
			t.Error("authenticated origin probe")
		}
		w.WriteHeader(status)
	}))
	origin.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	origin.StartTLS()
	defer origin.Close()
	c := generated.IngressChange{Hostname: "console.example", OriginServerName: "console.example", OriginService: origin.URL, OriginIdentityDigest: digestBytes(cert.Certificate[0])}
	p := serverconfig.Profile{RemoteRead: serverconfig.RemoteRead{Enabled: true, ConfigurationValid: true, BindAddress: origin.Listener.Addr().String(), PublicOrigin: "https://console.example", TLSCertificatePath: certPath, TLSPrivateKeyPath: keyPath}}
	if _, e = probeBootstrapOrigin(context.Background(), p, c); e != nil {
		t.Fatal(e)
	}
	status = http.StatusOK
	if _, e = probeBootstrapOrigin(context.Background(), p, c); e == nil {
		t.Fatal("unauthenticated origin accepted")
	}
	status = http.StatusForbidden
	c.OriginIdentityDigest = digestBytes([]byte("foreign certificate"))
	if _, e = probeBootstrapOrigin(context.Background(), p, c); e == nil {
		t.Fatal("wrong certificate accepted")
	}
	c.OriginIdentityDigest = digestBytes(cert.Certificate[0])
	p.RemoteRead.Enabled = false
	if _, e = probeBootstrapOrigin(context.Background(), p, c); e == nil {
		t.Fatal("disabled protected origin accepted")
	}
}
func TestBootstrapStaysLocalAndCannotUseMissingPolicy(t *testing.T) {
	if (&ingressBootstrapComposition{}).check(context.Background(), ingress.Staged{}) == nil {
		t.Fatal("missing setup authority accepted")
	}
	for _, path := range []string{"/api/v1/network/ingress/draft", "/api/v1/network/ingress/observe"} {
		if api.RemoteReadRequestAllowed(http.MethodPost, path) {
			t.Fatal("bootstrap exposed over remote browser boundary")
		}
	}
}

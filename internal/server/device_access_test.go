package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"net/http"
	"net/http/httptest"
	"testing"
)

type deviceAccessFixture struct {
	allowed bool
	calls   int
}

func (f *deviceAccessFixture) AuthorizeDevice(context.Context, identity.Principal) error {
	f.calls++
	if !f.allowed {
		return failure.New("AUTHORIZATION_DENIED", "device", false)
	}
	return nil
}
func TestDeviceAccessCheckedForEveryRequest(t *testing.T) {
	f := &deviceAccessFixture{}
	app := &testApplication{}
	s := &service{config: Config{Application: app, Results: testResultFactory(), DeviceAuthorizer: f}}
	ctx := identity.WithVerifiedPrincipal(context.Background(), identity.Principal{ID: "human-a", Method: identity.LocalOSPeerMethod, DeviceID: "device-a"})
	for _, allowed := range []bool{false, true, false} {
		f.allowed = allowed
		w := httptest.NewRecorder()
		s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/synthetic", nil).WithContext(ctx))
		want := http.StatusForbidden
		if allowed {
			want = http.StatusNotFound
		}
		if w.Code != want {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	if f.calls != 3 {
		t.Fatal("cached device decision", f.calls)
	}
	s.config.DeviceAuthorizer = nil
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil).WithContext(ctx))
	if w.Code != 403 || app.healthCalls.Load() != 0 {
		t.Fatal("missing guard disclosed health")
	}
	ctx = identity.WithVerifiedPrincipal(context.Background(), identity.Principal{ID: "human-a", Method: identity.LocalOSPeerMethod})
	w = httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/synthetic", nil).WithContext(ctx))
	if w.Code != 404 {
		t.Fatal("legacy local identity changed")
	}
}

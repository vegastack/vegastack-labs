package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Exercises the actual browser authentication middleware before body parsing.
// Store-backed target grants and revision checks are covered by the Linux API integration.
func TestHostLifecycleBrowserSessionBoundary(t *testing.T) {
	for _, path := range []string{"/api/v1/host-discovery-targets/draft", "/api/v1/host-observations", "/api/v1/host-adoptions/draft", "/api/v1/host-actions/draft", "/api/v1/host-access/draft", "/api/v1/host-replacements"} {
		for _, mode := range []string{"valid", "missing-session", "expired-session", "foreign-origin"} {
			t.Run(path+"/"+mode, func(t *testing.T) {
				auth, _, sessions := newBrowserAuthFixture(t)
				req := httptest.NewRequest("POST", "https://console.example"+path, nil)
				req.Header.Set("Origin", "https://console.example")
				req.Header.Set("Cf-Access-Jwt-Assertion", "verified-provider-assertion")
				if mode != "missing-session" {
					req.AddCookie(&http.Cookie{Name: BrowserSessionCookieName, Value: sessions.raw})
				}
				if mode == "expired-session" {
					sessions.validationErr = errors.New("expired")
				}
				if mode == "foreign-origin" {
					req.Header.Set("Origin", "https://other.example")
				}
				calls := 0
				res := httptest.NewRecorder()
				auth.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(204) })).ServeHTTP(res, req)
				if mode == "valid" {
					if res.Code != 204 || calls != 1 {
						t.Fatalf("valid request: %d/%d", res.Code, calls)
					}
				} else if res.Code != 401 || calls != 0 {
					t.Fatalf("denied request reached handler: %d/%d", res.Code, calls)
				}
			})
		}
	}
}

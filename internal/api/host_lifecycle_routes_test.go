package api

import "testing"

func TestHostLifecycleBrowserRoutesAreFinite(t *testing.T) {
	for _, path := range []string{"/api/v1/host-discovery-targets/draft", "/api/v1/host-observations", "/api/v1/host-adoptions/draft", "/api/v1/host-actions/draft", "/api/v1/host-access/draft"} {
		if !RemoteReadRequestAllowed("POST", path) {
			t.Errorf("required lifecycle route not exposed: %s", path)
		}
	}
	for _, path := range []string{"/api/v1/hosts/host-a", "/api/v1/host-observations/observation-a"} {
		if !RemoteReadRequestAllowed("GET", path) {
			t.Errorf("required lifecycle read not exposed: %s", path)
		}
	}
	for _, path := range []string{"/api/v1/credential-lifecycle-drafts", "/api/v1/plans/plan-a/acknowledgements", "/api/v1/host-actions/execute", "/api/v1/setup"} {
		if RemoteReadRequestAllowed("POST", path) {
			t.Errorf("unapproved route exposed: %s", path)
		}
	}
}

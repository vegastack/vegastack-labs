package metadata

import "testing"

func TestNativeProducerLookupCannotWidenReadBoundary(t *testing.T) {
	for name, mutate := range map[string]func(*EndpointDefinition){
		"browser":   func(e *EndpointDefinition) { e.Audiences = append(e.Audiences, AudienceBrowser) },
		"remote":    func(e *EndpointDefinition) { e.TransportScope = "any" },
		"oversized": func(e *EndpointDefinition) { e.MaxRequestBytes = 16384 },
		"path":      func(e *EndpointDefinition) { e.Path = "/api/v1/qualification/producer" },
		"response":  func(e *EndpointDefinition) { e.DataSchema = "vegastack-labs.dev/native-collect-data" },
	} {
		t.Run(name, func(t *testing.T) {
			r := Current()
			for i := range r.Endpoints {
				if r.Endpoints[i].ID == "api.v1.qualification.producer" {
					mutate(&r.Endpoints[i])
					if Validate(r) == nil {
						t.Fatal("widened native lookup accepted")
					}
					return
				}
			}
			t.Fatal("lookup missing")
		})
	}
}

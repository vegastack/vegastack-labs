package contractgen

import (
	"bytes"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/metadata"
)

func TestServiceBrowserMethodsRemainDistinct(t *testing.T) {
	endpoints, err := browserReadEndpoints(metadata.Current())
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	renderFiniteReadClient(&output, endpoints)
	source := output.String()
	for _, method := range []string{"listServices", "getService", "getServiceObservation", "getServiceDeployment"} {
		if strings.Count(source, "  readonly "+method+":") != 1 || strings.Count(source, "    async "+method+"(") != 1 {
			t.Errorf("expected one interface declaration and implementation for %s", method)
		}
	}
	for _, expected := range []string{
		`readonly getService: (path: { readonly serviceID: string }`,
		`readonly getServiceObservation: (path: { readonly serviceID: string }`,
		`readonly listServices: (query?: ServiceReadQuery`,
		`Promise<ReadResult<ServiceRecord>>`,
		`Promise<ReadResult<ServiceList>>`,
		`Promise<ReadResult<ServiceObservation>>`,
		`"api.v1.services.get"`,
		`"api.v1.services.list"`,
		`"/api/v1/services" + serviceReadQuery(query)`,
		`"api.v1.services.observation.get"`,
		`if (data.definition.serviceId !== path.serviceID)`,
		`if (data.serviceId !== path.serviceID)`,
		`if (data.request.definition.serviceId !== path.serviceID)`,
	} {
		if !strings.Contains(source, expected) {
			t.Errorf("service browser client missing %s", expected)
		}
	}
	if strings.Contains(source, "async getServices(") || strings.Contains(source, "import-drafts") {
		t.Fatal("service browser reads contain ambiguous method or operator-only import mutation")
	}
}

func TestServiceBrowserQueryMatchesRawURLContract(t *testing.T) {
	artifacts, err := Generate(metadata.Current())
	if err != nil {
		t.Fatal(err)
	}
	for _, artifact := range artifacts {
		if artifact.Path != browserClientPath {
			continue
		}
		source := string(artifact.Content)
		start := strings.Index(source, "export interface ServiceReadQuery {")
		if start < 0 {
			t.Fatal("missing service query type")
		}
		query := source[start:]
		end := strings.Index(query, "}\n")
		if end < 0 {
			t.Fatal("unterminated service query type")
		}
		query = query[:end]
		if strings.Contains(query, `"schema"`) || strings.Contains(query, `"schemaVersion"`) {
			t.Fatal("URL query incorrectly requires a JSON envelope")
		}
		for _, expected := range []string{`function serviceReadQuery(query: ServiceReadQuery)`, `decodeServiceReadQuery(query)`, `params.set("after", checked.after)`, `params.set("limit", String(checked.limit))`} {
			if !strings.Contains(source, expected) {
				t.Errorf("missing strict service URL serializer %s", expected)
			}
		}
		return
	}
	t.Fatal("missing browser client")
}

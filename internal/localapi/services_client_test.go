package localapi

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

func TestServiceRemoteArgumentsBindExactIDAndPagination(t *testing.T) {
	for _, tc := range []struct {
		op, path string
		want     []string
	}{
		{"api.v1.services.list", "/api/v1/services?after=service-a&limit=7", []string{"service", "list", "--after", "service-a", "--limit", "7"}},
		{"api.v1.services.get", "/api/v1/services/service-a", []string{"service", "show", "--service-id", "service-a"}},
		{"api.v1.services.observation.get", "/api/v1/services/service-a/observation", []string{"service", "observe", "--service-id", "service-a"}},
		{"api.v1.services.import-drafts.create", "/api/v1/services/import-drafts", []string{"service", "import", "draft"}},
	} {
		if got := remoteCommandArguments(requestSpec{command: tc.op, path: tc.path}); !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("%s got=%v", tc.path, got)
		}
	}
	for _, path := range []string{"/api/v1/services?limit=0", "/api/v1/services?limit=101", "/api/v1/services?limit=1&limit=2", "/api/v1/services?after=../private", "/api/v1/services?url=private", "https://invalid.example/api/v1/services"} {
		if got := remoteCommandArguments(requestSpec{command: "api.v1.services.list", path: path}); got != nil {
			t.Fatalf("unbounded path %s got=%v", path, got)
		}
	}
	for _, path := range []string{"/api/v1/services/service/../other", "/api/v1/services/service-a?scope=all"} {
		if got := remoteCommandArguments(requestSpec{command: "api.v1.services.get", path: path}); got != nil {
			t.Fatalf("unbounded ID %s got=%v", path, got)
		}
	}
}
func TestServiceClientRejectsInvalidInputBeforeTransport(t *testing.T) {
	client := &client{}
	if _, err := client.ListServices(context.Background(), serverconfig.Profile{}, "", 101); err == nil {
		t.Fatal("unbounded page")
	}
	if _, err := client.GetService(context.Background(), serverconfig.Profile{}, "../private"); err == nil {
		t.Fatal("unbounded ID")
	}
	if _, err := client.ObserveService(context.Background(), serverconfig.Profile{}, "https://invalid.example"); err == nil {
		t.Fatal("arbitrary origin")
	}
	if _, err := client.DraftServiceImport(context.Background(), serverconfig.Profile{}, generated.ServiceImportDraftRequest{}); err == nil {
		t.Fatal("invalid draft")
	}
}
func TestServiceListResponseBindsScopeOrderAndRevision(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	record := generated.ServiceRecord{Schema: generated.SchemaIDServiceRecord, SchemaVersion: "1.0.0", Definition: generated.ServiceDefinition{Schema: generated.SchemaIDServiceDefinition, SchemaVersion: "1.0.0", ServiceID: "service-b", EnvironmentID: "env-a", OwnerID: "human-a", HostID: "host-a", HostIdentityDigest: digest, BindingID: "binding-a", BindingDigest: digest}, Revision: 1, RegistrationStatus: "registered", HostAdmission: "not-verified", RegisteredAt: "2026-10-26T00:00:00Z", StateRevision: 3, RecoveryEpoch: 1}
	page := generated.ServiceList{Schema: generated.SchemaIDServiceList, SchemaVersion: "1.0.0", Services: []generated.ServiceRecord{record}, NextAfter: "service-b", StateRevision: 3, RecoveryEpoch: 1}
	result := generated.RunResult{StateRevision: 3, RecoveryEpoch: 1}
	if !validServiceList(page, result, "service-a", 1) {
		t.Fatal("valid page rejected")
	}
	if validServiceList(page, result, "service-b", 1) {
		t.Fatal("record outside continuation accepted")
	}
	page.NextAfter = "service-c"
	if validServiceList(page, result, "service-a", 1) {
		t.Fatal("unbound cursor accepted")
	}
	page.NextAfter = ""
	page.Services[0].RecoveryEpoch = 0
	if validServiceList(page, result, "service-a", 1) {
		t.Fatal("old epoch accepted")
	}
}

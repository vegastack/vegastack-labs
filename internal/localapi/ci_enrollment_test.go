package localapi

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

func TestCIEnrollmentRemoteArgumentsBindExactIDAndPagination(t *testing.T) {
	for _, tc := range []struct {
		op, path string
		want     []string
	}{
		{"api.v1.ci.enrollments.list", "/api/v1/ci/enrollments?after=service-a&limit=7", []string{"ci", "enrollment", "list", "--after", "service-a", "--limit", "7"}},
		{"api.v1.ci.enrollments.get", "/api/v1/ci/enrollments/service-a", []string{"ci", "enrollment", "show", "--enrollment-id", "service-a"}},
		{"api.v1.ci.enrollments.drafts.create", "/api/v1/ci/enrollments/drafts", []string{"ci", "enrollment", "draft"}},
	} {
		if got := remoteCommandArguments(requestSpec{command: tc.op, path: tc.path}); !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("%s got=%v", tc.path, got)
		}
	}
	for _, path := range []string{"/api/v1/ci/enrollments?limit=0", "/api/v1/ci/enrollments?limit=101", "/api/v1/ci/enrollments?limit=1&limit=2", "/api/v1/ci/enrollments?after=../private", "/api/v1/ci/enrollments?url=private", "https://invalid.example/api/v1/ci/enrollments"} {
		if got := remoteCommandArguments(requestSpec{command: "api.v1.ci.enrollments.list", path: path}); got != nil {
			t.Fatalf("unbounded path %s got=%v", path, got)
		}
	}
	for _, path := range []string{"/api/v1/ci/enrollments/service/../other", "/api/v1/ci/enrollments/service-a?scope=all"} {
		if got := remoteCommandArguments(requestSpec{command: "api.v1.ci.enrollments.get", path: path}); got != nil {
			t.Fatalf("unbounded ID %s got=%v", path, got)
		}
	}
}
func TestCIEnrollmentClientRejectsInvalidInputBeforeTransport(t *testing.T) {
	client := &client{}
	if _, err := client.ListCIEnrollments(context.Background(), serverconfig.Profile{}, "", 101); err == nil {
		t.Fatal("unbounded page")
	}
	if _, err := client.GetCIEnrollment(context.Background(), serverconfig.Profile{}, "../private"); err == nil {
		t.Fatal("unbounded ID")
	}
	if _, err := client.DraftCIEnrollment(context.Background(), serverconfig.Profile{}, generated.CiEnrollmentDraftRequest{}); err == nil {
		t.Fatal("invalid draft")
	}
}
func TestCIEnrollmentListResponseBindsScopeOrderAndRevision(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	record := generated.CiEnrollmentRecord{Schema: generated.SchemaIDCiEnrollmentRecord, SchemaVersion: "1.0.0", Definition: generated.CiEnrollmentDefinition{Schema: generated.SchemaIDCiEnrollmentDefinition, SchemaVersion: "1.0.0", EnrollmentID: "service-b", OwnerID: "human-a", BindingID: "binding-a", BindingDigest: digest}, Revision: 1, RegistrationStatus: "registered", AdmissionStatus: "not-qualified", RegisteredAt: "2026-10-26T00:00:00Z", StateRevision: 3, RecoveryEpoch: 1}
	page := generated.CiEnrollmentList{Schema: generated.SchemaIDCiEnrollmentList, SchemaVersion: "1.0.0", Enrollments: []generated.CiEnrollmentRecord{record}, NextAfter: "service-b", StateRevision: 3, RecoveryEpoch: 1}
	result := generated.RunResult{StateRevision: 3, RecoveryEpoch: 1}
	if !validCiEnrollmentList(page, result, "service-a", 1) {
		t.Fatal("valid page rejected")
	}
	if validCiEnrollmentList(page, result, "service-b", 1) {
		t.Fatal("record outside continuation accepted")
	}
	page.NextAfter = "service-c"
	if validCiEnrollmentList(page, result, "service-a", 1) {
		t.Fatal("unbound cursor accepted")
	}
	page.NextAfter = ""
	page.Enrollments[0].RecoveryEpoch = 0
	if validCiEnrollmentList(page, result, "service-a", 1) {
		t.Fatal("old epoch accepted")
	}
}

func TestCIEnrollmentClientValidatesActualUnixResponse(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	record := generated.CiEnrollmentRecord{Schema: generated.SchemaIDCiEnrollmentRecord, SchemaVersion: "1.0.0", Definition: generated.CiEnrollmentDefinition{Schema: generated.SchemaIDCiEnrollmentDefinition, SchemaVersion: "1.0.0", EnrollmentID: "enrollment-a", OwnerID: "human-a", BindingID: "binding-a", BindingDigest: digest}, Revision: 1, RegistrationStatus: "registered", AdmissionStatus: "not-qualified", RegisteredAt: "2026-10-27T00:00:00Z", StateRevision: 3, RecoveryEpoch: 1}
	for _, bad := range []bool{false, true} {
		t.Run(map[bool]string{false: "exact", true: "wrong-enrollment"}[bad], func(t *testing.T) {
			data := record
			if bad {
				data.Definition.EnrollmentID = "another"
			}
			env, err := clientTestFactory().Success("api.v1.ci.enrollments.get", 1, 3, data)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(env)
			if err != nil {
				t.Fatal(err)
			}
			raw = append(raw, '\n')
			dir, err := os.MkdirTemp("/tmp", "vsk-ci-client-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.RemoveAll(dir) })
			path := filepath.Join(dir, "api.sock")
			listener, err := net.Listen("unix", path)
			if err != nil {
				t.Fatal(err)
			}
			h := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.URL.RequestURI() != "/api/v1/ci/enrollments/enrollment-a" {
					t.Error("wrong exact request", r.Method, r.URL)
				}
				w.Header().Set("Content-Type", "application/json")
				w.Write(raw)
			})}
			go h.Serve(listener)
			defer h.Close()
			response, err := NewClient(clientTestFactory()).GetCIEnrollment(context.Background(), serverconfig.Profile{SocketPath: path}, "enrollment-a")
			if bad {
				if err == nil || len(response.Raw) != 0 {
					t.Fatal("substituted enrollment accepted", response, err)
				}
			} else if err != nil || string(response.Raw) != string(raw) || response.Data.AdmissionStatus != "not-qualified" {
				t.Fatal(response, err)
			}
		})
	}
}

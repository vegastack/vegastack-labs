package cli

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"strings"
	"testing"
)

type ciEnrollmentControlFixture struct {
	*stubControlOperations
	calls             int
	after, id, config string
	limit             int
	request           generated.CiEnrollmentDraftRequest
}

func (f *ciEnrollmentControlFixture) ListCIEnrollments(_ context.Context, config, after string, limit int) (localapi.TypedResponse[generated.CiEnrollmentList], error) {
	f.calls++
	f.config = config
	f.after = after
	f.limit = limit
	return localapi.TypedResponse[generated.CiEnrollmentList]{Data: generated.CiEnrollmentList{Enrollments: []generated.CiEnrollmentRecord{}}, Raw: []byte("{\"ciFixture\":true}\n")}, nil
}
func (f *ciEnrollmentControlFixture) GetCIEnrollment(_ context.Context, config, id string) (localapi.TypedResponse[generated.CiEnrollmentRecord], error) {
	f.calls++
	f.config = config
	f.id = id
	return localapi.TypedResponse[generated.CiEnrollmentRecord]{Data: generated.CiEnrollmentRecord{Definition: generated.CiEnrollmentDefinition{EnrollmentID: id}, RegistrationStatus: "registered", AdmissionStatus: "not-qualified"}, Raw: []byte("{\"ciFixture\":true}\n")}, nil
}
func (f *ciEnrollmentControlFixture) DraftCIEnrollment(_ context.Context, config string, in generated.CiEnrollmentDraftRequest) (localapi.TypedResponse[generated.DeclarationRevision], error) {
	f.calls++
	f.config = config
	f.request = in
	return f.grantResponse, nil
}
func TestCIEnrollmentCLIThinProtectedSurface(t *testing.T) {
	raw, _ := json.Marshal(generated.CiEnrollmentDraftRequest{Schema: generated.SchemaIDCiEnrollmentDraftRequest, SchemaVersion: "1.0.0", EnrollmentID: "enrollment-a", BindingID: "binding-a", IdempotencyKey: "enroll-a", ReasonDigest: "sha256:" + strings.Repeat("a", 64)})
	for _, tc := range []struct {
		args []string
		want string
	}{{[]string{"list", "--after", "enrollment-a", "--limit", "7"}, "No CI registrations"}, {[]string{"show", "--enrollment-id", "enrollment-a"}, "not-qualified"}, {[]string{"draft", "--file", "draft.json"}, "Draft declaration"}} {
		f := &ciEnrollmentControlFixture{stubControlOperations: successfulControlOperations(t)}
		args := append([]string{"ci", "enrollment"}, tc.args...)
		args = append(args, "--config", "profile.json")
		code, out, stderr := runTestAppWithOptions(t, context.Background(), args, nil, WithControlOperations(f, &stubFileReader{content: raw}))
		if code != 0 || stderr != "" || f.calls != 1 || f.config != "profile.json" || !strings.Contains(out, tc.want) {
			t.Fatal(args, code, out, stderr, f)
		}
		if tc.args[0] == "list" && (f.after != "enrollment-a" || f.limit != 7) {
			t.Fatal(f)
		}
	}
	for _, args := range [][]string{{"list", "--limit", "0"}, {"list", "--limit", "101"}, {"show", "--enrollment-id", "../private"}, {"draft", "--file", "draft.json"}} {
		f := &ciEnrollmentControlFixture{stubControlOperations: successfulControlOperations(t)}
		a := append([]string{"ci", "enrollment"}, args...)
		a = append(a, "--config", "profile.json", "--output", "json")
		code, _, _ := runTestAppWithOptions(t, context.Background(), a, nil, WithControlOperations(f, &stubFileReader{content: []byte(`{"enrollmentId":"enrollment-a","repository":"private-owner/private-repo"}`)}))
		if code == 0 || f.calls != 0 {
			t.Fatal("unbounded input reached controller", a)
		}
	}
	f := &ciEnrollmentControlFixture{stubControlOperations: successfulControlOperations(t)}
	code, out, _ := runTestAppWithOptions(t, context.Background(), []string{"ci", "enrollment", "show", "--enrollment-id", "enrollment-a", "--config", "profile.json", "--output", "json"}, nil, WithControlOperations(f, nil))
	if code != 0 || strings.TrimSpace(out) != `{"ciFixture":true}` {
		t.Fatal(code, out)
	}
}

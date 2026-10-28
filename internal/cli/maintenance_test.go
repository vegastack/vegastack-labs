package cli

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/debianbaseline"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"strings"
	"testing"
)

type maintenanceCLIFixture struct {
	*stubControlOperations
	calls int
}

func (f *maintenanceCLIFixture) DiagnoseMaintenance(context.Context, string, string) (localapi.TypedResponse[generated.MaintenanceDiagnosis], error) {
	f.calls++
	return localapi.TypedResponse[generated.MaintenanceDiagnosis]{Data: generated.MaintenanceDiagnosis{HostID: "host-a", Status: "stale", NewAdmissionBlocked: true}, Raw: []byte(`{"fixture":true}`)}, nil
}
func (f *maintenanceCLIFixture) DraftMaintenance(context.Context, string, generated.MaintenanceDraftRequest) (localapi.TypedResponse[generated.DeclarationRevision], error) {
	f.calls++
	return localapi.TypedResponse[generated.DeclarationRevision]{Data: generated.DeclarationRevision{DeclarationID: "maintenance-a", Revision: 1}, Raw: []byte(`{"fixture":true}`)}, nil
}
func TestMaintenanceCLIReportsPreparationAndUnsupportedExecution(t *testing.T) {
	q := generated.MaintenanceDraftRequest{Schema: generated.SchemaIDMaintenanceDraftRequest, SchemaVersion: "1.0.0", DeclarationID: "maintenance-a", ExpectedRevision: 1, TargetIDs: []string{"host-a"}, CanaryHostID: "host-a", Action: "repair", ReasonDigest: hostaction.Digest("reason")}
	raw, _ := json.Marshal(q)
	for _, tc := range []struct {
		args []string
		want string
	}{{[]string{"diagnose", "--host-id", "host-a"}, "Baseline: stale"}, {[]string{"draft", "--file", "draft.json"}, "Execution: unsupported"}} {
		f := &maintenanceCLIFixture{stubControlOperations: successfulControlOperations(t)}
		args := append([]string{"maintenance"}, tc.args...)
		args = append(args, "--config", "profile.json")
		code, out, stderr := runTestAppWithOptions(t, context.Background(), args, nil, WithControlOperations(f, &stubFileReader{content: raw}))
		if code != 0 || stderr != "" || f.calls != 1 || !strings.Contains(out, tc.want) {
			t.Fatal(code, out, stderr, f.calls)
		}
	}
	f := &maintenanceCLIFixture{stubControlOperations: successfulControlOperations(t)}
	code, _, _ := runTestAppWithOptions(t, context.Background(), []string{"maintenance", "draft", "--file", "draft.json", "--config", "profile.json"}, nil, WithControlOperations(f, &stubFileReader{content: []byte(`{"action":"repair","shell":"danger"}`)}))
	if code == 0 || f.calls != 0 {
		t.Fatal("unbounded input reached server")
	}
}

type maintenanceRepairFixture struct {
	*maintenanceCLIFixture
	submitted     int
	received      generated.HostActionRequest
	diagnosisHost string
	state, epoch  int64
}

func (f *maintenanceRepairFixture) DiagnoseMaintenance(_ context.Context, _ string, id string) (localapi.TypedResponse[generated.MaintenanceDiagnosis], error) {
	f.calls++
	if f.diagnosisHost != "" {
		id = f.diagnosisHost
	}
	return localapi.TypedResponse[generated.MaintenanceDiagnosis]{Data: generated.MaintenanceDiagnosis{HostID: id, StateRevision: f.state, RecoveryEpoch: f.epoch, Status: "failed", NewAdmissionBlocked: true}}, nil
}
func (f *maintenanceRepairFixture) SubmitHostAction(_ context.Context, _ string, q generated.HostActionRequest) (localapi.TypedResponse[generated.HostActionSubmission], error) {
	f.submitted++
	f.received = q
	return localapi.TypedResponse[generated.HostActionSubmission]{Data: generated.HostActionSubmission{DraftID: "action-a", DeclarationID: "action-a", ContentDigest: hostaction.Digest(q)}, Raw: []byte(`{"fixture":true}`)}, nil
}
func TestMaintenanceRepairDelegatesExactExistingRequestAndRejectsScopeDrift(t *testing.T) {
	// The wrapper must forward the caller's existing request unchanged. The
	// protected API remains responsible for baseline policy/rendering/grants.
	request := syntheticRoleRequest(t)
	request.ActionID = "debian.baseline.apply"
	role := syntheticRoleInput()
	role.ProfileLock.OSFamily = "debian"
	role.ProfileLock.OSVersion = "13.6"
	role.ProfileLock.Architecture = "amd64"
	role.ProfileLock.Backend = "iptables-nft"
	role.ProfileLock.Packages = []generated.AccessPackage{{Schema: generated.SchemaIDAccessPackage, SchemaVersion: "1.0.0", Name: "auditd", Version: "fixture"}}
	baseline := generated.DebianBaselineInput{Schema: generated.SchemaIDDebianBaselineInput, SchemaVersion: "1.0.0", HostID: "test-host", HostIdentityDigest: request.ConsoleConfirmation.HostIdentityDigest, ProfileID: "test-profile", ProfileLock: role.ProfileLock, ProfileLockDigest: hostaction.Digest(role.ProfileLock), RoleID: "control", ActionVersion: "1.0.0", AutomationUID: 1001, ControlIDs: []string{"linux.audit-bounded"}, RecoverySourcePrefixes: []string{"192.0.2.1/32"}, UpdateOwner: "operator", TimeOwner: "chrony", AuditPaths: []string{"/etc/passwd"}, AppArmorProfiles: []generated.BaselineApparmorProfile{}, AIDE: generated.BaselineAidePolicy{Schema: generated.SchemaIDBaselineAidePolicy, SchemaVersion: "1.0.0", ScopePaths: []string{}, ScopeDigest: hostaction.Digest([]string{})}, Resources: []generated.BaselineResourceLimit{}, KernelSettings: []generated.BaselineKernelSetting{}, Volumes: []generated.HostVolumeBinding{}}
	baseline.RenderedPolicyDigest = debianbaseline.PolicyDigest(baseline)
	baselineRaw, _ := json.Marshal(baseline)
	if _, e := debianbaseline.DecodeDesiredInput(baselineRaw); e != nil {
		t.Fatal("invalid baseline fixture", e)
	}
	request.ActionInput = string(baselineRaw)
	request.ActionInputDigest = hostaction.BytesDigest(baselineRaw)
	for _, tc := range []struct {
		name       string
		mutate     func(*generated.HostActionRequest, *maintenanceRepairFixture)
		wantSubmit int
	}{
		{"exact", func(q *generated.HostActionRequest, f *maintenanceRepairFixture) {}, 1},
		{"different-host", func(q *generated.HostActionRequest, f *maintenanceRepairFixture) { q.HostID = "other-host" }, 0},
		{"different-action", func(q *generated.HostActionRequest, f *maintenanceRepairFixture) { q.ActionID = "debian.role.apply" }, 0},
		{"stale-state", func(q *generated.HostActionRequest, f *maintenanceRepairFixture) { f.state++ }, 0},
		{"stale-epoch", func(q *generated.HostActionRequest, f *maintenanceRepairFixture) { f.epoch++ }, 0},
		{"different-diagnosed-host", func(q *generated.HostActionRequest, f *maintenanceRepairFixture) { f.diagnosisHost = "other-host" }, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := request
			f := &maintenanceRepairFixture{maintenanceCLIFixture: &maintenanceCLIFixture{stubControlOperations: successfulControlOperations(t)}, state: q.ExpectedStateRevision, epoch: q.RecoveryEpoch}
			tc.mutate(&q, f)
			raw, _ := json.Marshal(q)
			code, out, _ := runTestAppWithOptions(t, context.Background(), []string{"maintenance", "repair", "--host-id", "test-host", "--config", "profile.json", "--file", "request.json"}, nil, WithControlOperations(f, &stubFileReader{content: raw}))
			if f.submitted != tc.wantSubmit || (tc.wantSubmit == 1 && (code != 0 || !strings.Contains(out, "No host action ran") || hostaction.Digest(f.received) != hostaction.Digest(q))) || (tc.wantSubmit == 0 && code == 0) {
				t.Fatal(code, out, f.submitted)
			}
		})
	}
}

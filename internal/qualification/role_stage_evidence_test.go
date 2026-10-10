package qualification

import (
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/linuxrole"
	"testing"
)

func reserveRoleEvidence(t *testing.T) []ProducerExecution {
	t.Helper()
	d := hostaction.Digest("synthetic-reserve-predicate")
	lock := generated.DebianProfileLock{Schema: generated.SchemaIDDebianProfileLock, SchemaVersion: "1.0.0", ImageDigest: d, OSFamily: "debian", OSVersion: "13.6", Architecture: "amd64", PackageSourceDigest: d, Packages: []generated.AccessPackage{{Schema: generated.SchemaIDAccessPackage, SchemaVersion: "1.0.0", Name: "systemd", Version: "1"}}, ExecutableVersion: "1.0.0", AnsibleVersion: "2.19.0", AnsibleExecutableDigest: d, CollectionDigest: d, RoleDigest: d, Backend: "iptables-nft"}
	in := generated.LinuxRoleInput{Schema: generated.SchemaIDLinuxRoleInput, SchemaVersion: "1.0.0", HostID: "reserve-host", HostIdentityDigest: d, ProfileID: "debian", ProfileLock: lock, ProfileLockDigest: hostaction.Digest(lock), RoleID: "reserve", StandbyRequired: true, ActionVersion: "1.0.0", AutomationUID: 1000, ControlIDs: []string{"linux.role-identity-paths", "linux.role-service-resources", "linux.reserve-no-workloads"}, AffectedBaselineControlIDs: []string{"linux.resource-health", "debian.accounts", "debian.ssh"}, BaselineSnapshotDigest: d, ExecutableDigest: d, ConfigDigest: d, ExpectedServiceState: "absent", Accounts: []generated.LinuxRoleAccount{{Schema: generated.SchemaIDLinuxRoleAccount, SchemaVersion: "1.0.0", Selector: "standby", UID: 1001, GID: 1001}}, Resources: generated.LinuxRoleResources{Schema: generated.SchemaIDLinuxRoleResources, SchemaVersion: "1.0.0", MemoryMaxBytes: 1 << 30, CPUQuotaPercent: 100, TasksMax: 100, MinimumFreeBytes: 1 << 30, MinimumFreePercent: 10, CapacityMemoryBytes: 2 << 30, CapacityCPUPercent: 200, CapacityTasks: 200}}
	for _, s := range []string{"config", "state", "runtime"} {
		in.Directories = append(in.Directories, generated.LinuxRoleDirectory{Schema: generated.SchemaIDLinuxRoleDirectory, SchemaVersion: "1.0.0", Selector: s, UID: 1001, GID: 1001, Mode: "0700", ExpectedState: "absent"})
	}
	in.RenderedPolicyDigest = linuxrole.PolicyDigest(in)
	in.RoleBindingDigest = linuxrole.RoleBindingDigest(in)
	if e := linuxrole.ValidateInput(in); e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(in)
	var out []ProducerExecution
	for i, action := range []string{"debian.role.apply", "debian.role.collect"} {
		e := ProducerExecution{Reference: generated.NativeProducerReference{HostID: in.HostID}, Plan: generated.Plan{Binding: generated.PlanBinding{StateRevision: int64(i + 1)}, HostAction: &generated.HostActionRequest{ActionID: action, ActionInput: string(raw)}, HostRoleScope: &generated.HostRoleScope{RoleID: in.RoleID, RoleBindingDigest: in.RoleBindingDigest}}, Receipt: generated.ExecutionReceipt{Status: "succeeded"}, Result: &generated.HostActionResult{Status: "succeeded", EffectObserved: true}}
		for _, id := range in.ControlIDs {
			e.Result.ControlMeasurements = append(e.Result.ControlMeasurements, generated.AccessMeasurement{ControlID: id, Status: "passed", SubjectHostID: in.HostID, SubjectIdentityDigest: in.HostIdentityDigest, ConfigurationDigest: hostaction.Digest(in), Role: &generated.RoleObservation{RoleID: in.RoleID, RoleBindingDigest: in.RoleBindingDigest, Verification: "effective-probe"}})
		}
		out = append(out, e)
	}
	return out
}
func TestRoleStageRequiresAppliedThenCompleteEffectiveCollection(t *testing.T) {
	e := reserveRoleEvidence(t)
	o := make([]generated.NativeObservation, 2)
	if err := validateRoleScenarioEvidence("role-reserve", e, o); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"collect-only", "missing-isolation", "partial", "old-collection", "wrong-role", "wrong-binding"} {
		t.Run(kind, func(t *testing.T) {
			e := reserveRoleEvidence(t)
			switch kind {
			case "collect-only":
				e = e[1:]
			case "missing-isolation":
				e[1].Result.ControlMeasurements = e[1].Result.ControlMeasurements[:2]
			case "partial":
				e[1].Result.Status = "partial"
			case "old-collection":
				e[1].Plan.Binding.StateRevision = 1
			case "wrong-role":
				e[1].Plan.HostRoleScope.RoleID = "application"
			case "wrong-binding":
				e[1].Result.ControlMeasurements[0].Role.RoleBindingDigest = hostaction.Digest("other")
			}
			if validateRoleScenarioEvidence("role-reserve", e, make([]generated.NativeObservation, len(e))) == nil {
				t.Fatal("incomplete role accepted")
			}
		})
	}
}
func TestRecoveryPositiveCannotReplaceNegativeScenarios(t *testing.T) {
	e, v := recoveryEvidenceFixture()
	e.ReplacementRecovery = &v
	if validateRoleScenarioEvidence("replacement-recovery", []ProducerExecution{e}, []generated.NativeObservation{{}}) == nil {
		t.Fatal("positive-only recovery qualified")
	}
}

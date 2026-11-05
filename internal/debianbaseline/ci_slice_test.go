package debianbaseline

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

func ciSliceInputFixture() generated.DebianBaselineInput {
	in := baselineInputFixture()
	in.RoleID = "host"
	in.ControlIDs = []string{"linux.resource-health"}
	in.ProfileLock.Packages[0].Name = "systemd"
	in.ProfileLockDigest = hostaction.Digest(in.ProfileLock)
	in.Resources = []generated.BaselineResourceLimit{{Schema: generated.SchemaIDBaselineResourceLimit, SchemaVersion: "1.0.0", Unit: "vsk-ci.slice", MemoryMaxBytes: 128 << 20, TasksMax: 128, CPUQuotaPercent: 100, MountPath: "/var/lib/vsk-ci", MinimumFreeBytes: 1 << 30, MinimumFreePercent: 20}}
	return in
}

func TestCISliceDesiredInputAcceptsOnlyOwnedRoleBoundary(t *testing.T) {
	for _, role := range []string{"host", "ci"} {
		t.Run(role, func(t *testing.T) {
			in := ciSliceInputFixture()
			in.RoleID = role
			raw, _ := json.Marshal(in)
			if _, err := DecodeDesiredInput(raw); err != nil {
				t.Fatalf("canonical CI boundary rejected: %v", err)
			}
		})
	}
	for _, tc := range []struct{ role, unit string }{{"control", "vsk-ci.slice"}, {"application", "vsk-ci.slice"}, {"host", "other.slice"}, {"host", "vsk-application.slice"}, {"host", "vsk-ci.scope"}, {"host", "vsk-ci@1.service"}, {"host", "../vsk-ci.slice"}, {"host", "Vsk-ci.slice"}, {"host", "vsk-ci.slice --all"}} {
		t.Run(tc.role+"/"+tc.unit, func(t *testing.T) {
			in := ciSliceInputFixture()
			in.RoleID = tc.role
			in.Resources[0].Unit = tc.unit
			raw, _ := json.Marshal(in)
			if _, err := DecodeDesiredInput(raw); err == nil {
				t.Fatal("unowned or unsafe unit accepted")
			}
		})
	}
	in := ciSliceInputFixture()
	in.RoleID = "control"
	in.Resources[0].Unit = "auditd.service"
	raw, _ := json.Marshal(in)
	if _, err := DecodeDesiredInput(raw); err != nil {
		t.Fatalf("existing service validation changed: %v", err)
	}
	for _, change := range []func(*generated.BaselineResourceLimit){func(r *generated.BaselineResourceLimit) { r.CPUQuotaPercent = 10001 }, func(r *generated.BaselineResourceLimit) { r.MinimumFreeBytes = 1 }, func(r *generated.BaselineResourceLimit) { r.MinimumFreePercent = 9 }} {
		in := ciSliceInputFixture()
		change(&in.Resources[0])
		raw, _ := json.Marshal(in)
		if _, err := DecodeDesiredInput(raw); err == nil {
			t.Fatal("existing resource bounds widened")
		}
	}
}

func TestCISliceHealthRequiresActiveCanonicalFiniteObservation(t *testing.T) {
	in := ciSliceInputFixture()
	valid := "ActiveState=active\nSubState=active\nFragmentPath=/etc/systemd/system/vsk-ci.slice\nMemoryMax=134217728\nTasksMax=128\nCPUQuotaPerSecUSec=1s\n"
	reader := fixtureReader{{Operation: ReadUnit, Selector: "vsk-ci.slice"}: []byte(valid), {Operation: ReadDisk, Selector: "/var/lib/vsk-ci"}: []byte(`{"Total":8589934592,"Free":4294967296}`)}
	check := func(t *testing.T, want bool) {
		t.Helper()
		rows, err := Collect(context.Background(), in, reader)
		if err != nil || len(rows) != 1 {
			t.Fatal(rows, err)
		}
		if (rows[0].Status == "passed") != want {
			t.Fatalf("unexpected actual resource observation: %+v", rows[0])
		}
		if rows[0].Baseline.NativeQualificationDigest != "" {
			t.Fatal("observation claimed native qualification")
		}
	}
	check(t, true)
	for _, tc := range []struct{ name, from, to string }{{"inactive", "ActiveState=active", "ActiveState=inactive"}, {"missing-fragment", "FragmentPath=/etc/systemd/system/vsk-ci.slice", "FragmentPath="}, {"foreign-fragment", "/etc/systemd/system/vsk-ci.slice", "/run/systemd/transient/vsk-ci.slice"}, {"unbounded-memory", "MemoryMax=134217728", "MemoryMax=infinity"}, {"wrong-tasks", "TasksMax=128", "TasksMax=129"}, {"unbounded-cpu", "CPUQuotaPerSecUSec=1s", "CPUQuotaPerSecUSec=infinity"}} {
		t.Run(tc.name, func(t *testing.T) {
			reader[ReadRequest{Operation: ReadUnit, Selector: "vsk-ci.slice"}] = []byte(strings.Replace(valid, tc.from, tc.to, 1))
			check(t, false)
		})
	}
	reader[ReadRequest{Operation: ReadUnit, Selector: "vsk-ci.slice"}] = []byte(valid)
	reader[ReadRequest{Operation: ReadDisk, Selector: "/var/lib/vsk-ci"}] = []byte(`{"Total":8589934592,"Free":1024}`)
	check(t, false)
}

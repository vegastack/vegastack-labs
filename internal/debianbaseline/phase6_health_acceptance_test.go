package debianbaseline

import (
	"context"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

// The existing integrated server fixture proves receipt-backed collection for
// time. These two controls lacked a focused effective-state success/denial
// check; use the owning collector and its existing isolated reader seam.
func TestPhase6ResourceKernelObservation(t *testing.T) {
	in := generated.DebianBaselineInput{ControlIDs: []string{"linux.resource-health", "linux.kernel-settings"}, Resources: []generated.BaselineResourceLimit{{Unit: "synthetic.slice", MemoryMaxBytes: 1048576, TasksMax: 64, CPUQuotaPercent: 50, MountPath: "/synthetic", MinimumFreeBytes: 100, MinimumFreePercent: 20}}, KernelSettings: []generated.BaselineKernelSetting{{Name: "kernel.kptr_restrict", Value: "2"}}}
	reader := fixtureReader{{Operation: ReadUnit, Selector: "synthetic.slice"}: []byte("MemoryMax=1048576\nTasksMax=64\nCPUQuotaPerSecUSec=500ms\n"), {Operation: ReadDisk, Selector: "/synthetic"}: []byte(`{"Total":1000,"Free":500}`), {Operation: ReadKernel, Selector: "kernel.kptr_restrict"}: []byte("2\n")}
	rows, e := Collect(context.Background(), in, reader)
	if e != nil || len(rows) != 2 {
		t.Fatal(rows, e)
	}
	for _, row := range rows {
		if row.Status != "passed" || row.Baseline.NativeQualificationDigest != "" {
			t.Fatal("fixture observation mislabeled or missing", row)
		}
	}
	for _, change := range []struct {
		key   ReadRequest
		value []byte
	}{{ReadRequest{Operation: ReadUnit, Selector: "synthetic.slice"}, []byte("MemoryMax=unbounded\nTasksMax=64\nCPUQuotaPerSecUSec=500ms\n")}, {ReadRequest{Operation: ReadDisk, Selector: "/synthetic"}, []byte(`{"Total":1000,"Free":99}`)}, {ReadRequest{Operation: ReadKernel, Selector: "kernel.kptr_restrict"}, []byte("0\n")}} {
		old := reader[change.key]
		reader[change.key] = change.value
		rows, e = Collect(context.Background(), in, reader)
		if e != nil {
			t.Fatal(e)
		}
		allPassed := true
		for _, row := range rows {
			allPassed = allPassed && row.Status == "passed"
		}
		if allPassed {
			t.Fatal("unsafe effective state accepted")
		}
		reader[change.key] = old
	}
	rows, e = Collect(context.Background(), in, fixtureReader{})
	if e != nil || len(rows) != 2 {
		t.Fatal(rows, e)
	}
	for _, row := range rows {
		if row.Status != "partial" || row.Baseline.Verification != "unavailable" {
			t.Fatal("missing observation passed", row)
		}
	}
}

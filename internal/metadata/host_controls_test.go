package metadata

import "testing"

func TestHostControlRequirementsClosed(t *testing.T) {
	rows := CurrentHostControlRequirements()
	seen := map[string]bool{}
	for _, row := range rows {
		if seen[row.Stage+":"+row.ControlID] || row.ControlID == "" || len(row.ProducerControlIDs) == 0 {
			t.Fatal("invalid requirement", row)
		}
		seen[row.Stage+":"+row.ControlID] = true
	}
	for _, id := range []string{"host.ssh-effective", "host.storage-encryption", "linux.control-service", "linux.reserve-no-workloads"} {
		if !(seen["baseline:"+id] || seen["role:"+id]) {
			t.Fatal("missing requirement", id)
		}
	}
}

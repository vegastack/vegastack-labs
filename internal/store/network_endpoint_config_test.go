package store

import "testing"

func TestNetworkEndpointExclusionConfigCopiesAndBoundsIDs(t *testing.T) {
	ids := []string{"excluded-synthetic"}
	out, e := normalizeConfig(Config{ToolVersion: "test", BuildVersion: "test", NetworkConnectExcludedHostIDs: ids})
	if e != nil {
		t.Fatal(e)
	}
	ids[0] = "mutated"
	if out.NetworkConnectExcludedHostIDs[0] != "excluded-synthetic" {
		t.Fatal("caller changed store exclusion policy")
	}
	for _, invalid := range [][]string{{"INVALID"}, {"same", "same"}, make([]string, 257)} {
		if _, e := normalizeConfig(Config{ToolVersion: "test", BuildVersion: "test", NetworkConnectExcludedHostIDs: invalid}); e == nil {
			t.Fatal("invalid exclusion policy accepted")
		}
	}
}

package slack

import "testing"

func TestProviderIDsPreserveSlackCase(t *testing.T) {
	config := testConfig()
	config.WorkspaceID = "T123ABC"
	config.SlackUserID = "U123ABC"
	config.ChannelID = "C123ABC"
	if !validConfig(config) {
		t.Fatal("provider IDs rejected by internal principal grammar")
	}
	config.HumanID = "HumanUppercase"
	if validConfig(config) {
		t.Fatal("internal human grammar widened")
	}
	config = testConfig()
	config.WorkspaceID = "T123\n"
	if validConfig(config) {
		t.Fatal("invalid provider ID accepted")
	}
}

package debianaccess

import (
	"strings"
	"testing"
)

const exactSudoJSON = `{"Defaults":[{"Options":[{"env_reset":true}]}],"User_Specs":[{"User_List":[{"username":"automation"}],"Host_List":[{"hostname":"ALL"}],"Cmnd_Specs":[{"runasusers":[{"username":"root"}],"Options":[{"authenticate":false}],"Commands":[{"command":"/usr/local/bin/vsk-labs host-action-once"}]}]}]}`

func TestSudoMachinePolicyAcceptsOnlyExactHelper(t *testing.T) {
	if e := validateSudoPolicy([]byte(exactSudoJSON), "automation", true); e != nil {
		t.Fatal(e)
	}
	for _, raw := range []string{strings.Replace(exactSudoJSON, "host-action-once", "*", 1), strings.Replace(exactSudoJSON, "/usr/local/bin/vsk-labs host-action-once", "ALL", 1), strings.Replace(exactSudoJSON, `"username":"root"`, `"username":"ALL"`, 1), strings.Replace(exactSudoJSON, `"authenticate":false`, `"authenticate":false,"setenv":true`, 1), strings.Replace(exactSudoJSON, `"username":"automation"`, `"usergroup":"sudo"`, 1), `{"User_Specs":[]}`, strings.Replace(exactSudoJSON, `"Defaults":`, `"Unknown":true,"Defaults":`, 1)} {
		if validateSudoPolicy([]byte(raw), "automation", true) == nil {
			t.Fatal("wider/unknown policy accepted")
		}
	}
}

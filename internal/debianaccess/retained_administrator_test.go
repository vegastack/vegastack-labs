package debianaccess

import (
	"encoding/json"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

func retainedInputForValidation(t *testing.T) generated.DebianAccessInput {
	t.Helper()
	in := validInput(t)
	a := validInput(t).Accounts[0]
	a.Name, a.Home, a.UID, a.GID, a.Role = "operator", "/home/operator", 1300, 1300, "human"
	a.RetainedAdministrator = &generated.AccessRetainedAdministrator{Schema: generated.SchemaIDAccessRetainedAdministrator, SchemaVersion: "1.0.0", Groups: []string{"docker", "operator", "sudo"}, SudoPolicyDigest: hostaction.Digest("existing-sudo")}
	in.Accounts = append(in.Accounts, a)
	in.SSHUsers = append(in.SSHUsers, a.Name)
	in.RenderedAccess.Accounts, in.RenderedAccess.SSHUsers = in.Accounts, in.SSHUsers
	in.RenderedAccessDigest = hostaction.Digest(in.RenderedAccess)
	return in
}

func TestRetainedAdministratorInputIsExplicitAndBound(t *testing.T) {
	in := retainedInputForValidation(t)
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeInput(raw); err != nil {
		t.Fatal("exact retained declaration rejected", err)
	}
	before := hostaction.Digest(in)
	in.Accounts[1].RetainedAdministrator.SudoPolicyDigest = hostaction.Digest("changed-sudo")
	if hostaction.Digest(in) == before {
		t.Fatal("retention not bound into input")
	}
	if ValidateInput(in) == nil {
		t.Fatal("changed rendered declaration accepted without new digest")
	}
}

func TestRetainedAdministratorInputRejectsWidening(t *testing.T) {
	for _, mode := range []string{"automation", "service", "two", "unsorted", "duplicate", "missing-primary", "root", "disk", "no-admin-group", "malformed-group", "not-ssh", "helper-not-ssh"} {
		t.Run(mode, func(t *testing.T) {
			in := retainedInputForValidation(t)
			r := in.Accounts[1].RetainedAdministrator
			switch mode {
			case "automation":
				in.Accounts[0].RetainedAdministrator = r
				in.Accounts[1].RetainedAdministrator = nil
			case "service":
				in.Accounts[1].Role = "service"
			case "two":
				a := validInput(t).Accounts[0]
				a.Name, a.Home, a.UID, a.GID, a.Role = "second", "/home/second", 1301, 1301, "human"
				a.RetainedAdministrator = &generated.AccessRetainedAdministrator{Schema: generated.SchemaIDAccessRetainedAdministrator, SchemaVersion: "1.0.0", Groups: []string{"second", "sudo"}, SudoPolicyDigest: r.SudoPolicyDigest}
				in.Accounts = append(in.Accounts, a)
				in.SSHUsers = append(in.SSHUsers, a.Name)
			case "unsorted":
				r.Groups = []string{"sudo", "operator"}
			case "duplicate":
				r.Groups = []string{"operator", "sudo", "sudo"}
			case "missing-primary":
				r.Groups = []string{"sudo"}
			case "root":
				r.Groups = []string{"operator", "root", "sudo"}
			case "disk":
				r.Groups = []string{"disk", "operator", "sudo"}
			case "no-admin-group":
				r.Groups = []string{"operator"}
			case "malformed-group":
				r.Groups = []string{"operator", "sudo", "x;bad"}
			case "not-ssh":
				in.SSHUsers = in.SSHUsers[:1]
			case "helper-not-ssh":
				in.SSHUsers = in.SSHUsers[1:]
			}
			if ValidateDesiredInput(in) == nil {
				t.Fatal("unbounded administrator retention accepted")
			}
		})
	}
}

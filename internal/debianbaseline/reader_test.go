package debianbaseline

import "testing"

func TestNativeReadRequestsCannotSelectCommands(t *testing.T) {
	for _, r := range []ReadRequest{{Operation: "shell", Selector: "id"}, {Operation: ReadUnit, Selector: "../ssh.service"}, {Operation: ReadFail2ban, Selector: "set sshd banip 192.0.2.1"}, {Operation: ReadPackage, Selector: "--help"}} {
		if _, _, e := readCommand(r); e == nil {
			t.Fatalf("accepted unbounded native read: %+v", r)
		}
	}
}

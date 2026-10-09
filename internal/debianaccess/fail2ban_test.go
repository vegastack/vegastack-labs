package debianaccess

import (
	"strings"
	"testing"
)

func TestFail2banPrefixCannotGrantAccess(t *testing.T) {
	good := "-N f2b-vsk-sshd\n-A f2b-vsk-sshd -s 192.0.2.7/32 -j DROP\n-A f2b-vsk-sshd -j RETURN\n-A INPUT -p tcp -m tcp --dport 22 -j f2b-vsk-sshd\n"
	if !validFail2banPrefix(good, "ipv4") {
		t.Fatal("bounded ban chain rejected")
	}
	for _, bad := range []string{strings.ReplaceAll(good, "DROP", "ACCEPT"), strings.ReplaceAll(good, "/32", "/24"), strings.ReplaceAll(good, "--dport 22", "--dport 443"), strings.ReplaceAll(good, "-j RETURN", "-j UNRELATED"), good + "-A f2b-vsk-sshd -j ACCEPT\n"} {
		if validFail2banPrefix(bad, "ipv4") {
			t.Fatal("unsafe prefix accepted", bad)
		}
	}
}

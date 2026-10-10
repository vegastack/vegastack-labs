//go:build linux

package qualification

import (
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"reflect"
	"strings"
	"testing"
)

func TestQEMUNetworkUsesClosedIndependentRestartPairs(t *testing.T) {
	scope := scopeFixture()
	wanted := map[string][]string{
		"controller": {"socket,id=subject,udp=127.0.0.1:19381,localaddr=127.0.0.1:19281", "socket,id=denied,udp=127.0.0.1:19382,localaddr=127.0.0.1:19282"},
		"subject":    {"socket,id=subject,udp=127.0.0.1:19281,localaddr=127.0.0.1:19381", "socket,id=denied,udp=127.0.0.1:19282,localaddr=127.0.0.1:19382"},
	}
	for id, expected := range wanted {
		args, err := QEMUArguments(scope, id)
		if err != nil {
			t.Fatal(err)
		}
		var network []string
		for i, arg := range args {
			if arg == "-netdev" {
				network = append(network, args[i+1])
			}
		}
		if !reflect.DeepEqual(network, expected) {
			t.Fatalf("%s network %v", id, network)
		}
	}
	if _, err := QEMUArguments(scope, "unowned"); err == nil {
		t.Fatal("unowned guest accepted")
	}
}

func TestQEMURecoveryPeersRemainDirectAfterFormerControllerStops(t *testing.T) {
	scope := scopeFixture()
	for i := range scope.Guests {
		scope.Guests[i].MemoryBytes = GiB
		scope.Guests[i].CPUs = 1
	}
	for _, role := range []string{"custodian", "replacement"} {
		g := scope.Guests[1]
		g.GuestID = role
		g.Role = role
		g.HostID = role + "-host"
		g.InstanceID = role + "-instance"
		g.HostIdentityDigest = hostaction.Digest(role + "-identity")
		g.SSHHostKeyDigest = hostaction.Digest(role + "-key")
		scope.Guests = append(scope.Guests, g)
	}
	pairs := map[string][]string{}
	macs := map[string]bool{}
	for _, g := range scope.Guests {
		args, err := QEMUArguments(scope, g.GuestID)
		if err != nil {
			t.Fatal(err)
		}
		for i, arg := range args {
			if arg == "-netdev" {
				value := args[i+1]
				if !strings.HasPrefix(value, "socket,id=") || !strings.Contains(value, ",udp=127.0.0.1:") || !strings.Contains(value, ",localaddr=127.0.0.1:") {
					t.Fatal("non-loopback backend")
				}
				pairs[g.Role] = append(pairs[g.Role], value)
			}
			if arg == "-device" && strings.HasPrefix(args[i+1], "virtio-net-pci,") {
				value := args[i+1]
				mac := value[strings.LastIndex(value, "mac=")+4:]
				if macs[mac] {
					t.Fatal("duplicate NIC MAC")
				}
				macs[mac] = true
			}
		}
	}
	for role, want := range map[string][]string{
		"replacement": {"socket,id=recovery-subject,udp=127.0.0.1:19385,localaddr=127.0.0.1:19285", "socket,id=recovery-custodian,udp=127.0.0.1:19386,localaddr=127.0.0.1:19286"},
		"subject":     {"socket,id=recovery-subject,udp=127.0.0.1:19285,localaddr=127.0.0.1:19385"},
		"custodian":   {"socket,id=recovery-custodian,udp=127.0.0.1:19286,localaddr=127.0.0.1:19386"},
	} {
		for _, expected := range want {
			found := false
			for _, got := range pairs[role] {
				found = found || got == expected
			}
			if !found {
				t.Fatalf("%s missing direct peer %s", role, expected)
			}
		}
	}
	if len(pairs["controller"]) != 4 || len(pairs["subject"]) != 3 || len(pairs["custodian"]) != 2 || len(pairs["replacement"]) != 3 || len(macs) != 12 {
		t.Fatal("topology widened or existing denied pair lost")
	}
	// There are exactly six reciprocal pairs: each bound UDP port has one peer,
	// so stopping the old controller does not remove the two new direct pairs.
	destinations := map[string]string{}
	for _, network := range pairs {
		for _, value := range network {
			parts := strings.Split(value, ",")
			remote := strings.TrimPrefix(parts[2], "udp=")
			local := strings.TrimPrefix(parts[3], "localaddr=")
			if _, exists := destinations[local]; exists {
				t.Fatal("duplicate UDP bind")
			}
			destinations[local] = remote
		}
	}
	for local, remote := range destinations {
		if destinations[remote] != local {
			t.Fatal("nonreciprocal UDP pair")
		}
	}
}

//go:build linux

package qualification

import (
	"reflect"
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

package localapi

import (
	"reflect"
	"testing"
)

func TestNetworkDescriptorRemoteArgumentsBindNode(t *testing.T) {
	args := remoteCommandArguments(requestSpec{command: "api.v1.hosts.connection-descriptor.get", path: "/api/v1/hosts/synthetic-host/connection-descriptor"})
	if !reflect.DeepEqual(args, []string{"connect", "--node", "synthetic-host", "--port", "22", "--path", "auto"}) {
		t.Fatal(args)
	}
	if args := remoteCommandArguments(requestSpec{command: "api.v1.hosts.connection-descriptor.get", path: "/api/v1/hosts/host/../other/connection-descriptor"}); args != nil {
		t.Fatal("unbounded remote path", args)
	}
}

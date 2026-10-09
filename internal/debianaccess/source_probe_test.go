package debianaccess

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"testing"
)

func TestPreparedDestinationKeepsStaticIdentityWithFreshReceipt(t *testing.T) {
	allowed := generated.AccessProbeTuple{Schema: generated.SchemaIDAccessProbeTuple, SchemaVersion: "1.0.0", HostID: "subject", IdentityDigest: hostaction.Digest("identity"), Address: "192.0.2.2", Port: 443, Protocol: "tcp"}
	actual := allowed
	actual.OwnershipDigest = hostaction.Digest("fresh-receipt")
	if !samePreparedDestination(actual, allowed) {
		t.Fatal("fresh proof required root allowlist reinstallation")
	}
	for _, field := range []string{"host", "identity", "address", "port", "protocol"} {
		changed := actual
		switch field {
		case "host":
			changed.HostID = "other"
		case "identity":
			changed.IdentityDigest = hostaction.Digest("other")
		case "address":
			changed.Address = "192.0.2.3"
		case "port":
			changed.Port = 22
		case "protocol":
			changed.Protocol = "udp"
		}
		if samePreparedDestination(changed, allowed) {
			t.Fatalf("widened %s accepted", field)
		}
	}
}

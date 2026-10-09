package debianaccess

import (
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"testing"
)

func TestAccessSequencePolicyCoverage(t *testing.T) {
	_, requests := accessSequenceFixture(t)
	var in generated.DebianAccessInput
	_ = json.Unmarshal([]byte(requests[0].ActionInput), &in)
	var local, remote generated.AccessProbeInput
	_ = json.Unmarshal([]byte(requests[2].ActionInput), &local)
	_ = json.Unmarshal([]byte(requests[3].ActionInput), &remote)
	if validateProbePolicy(in, []generated.AccessProbeInput{local, remote}) != nil {
		t.Fatal("valid actual policy rejected")
	}
	for _, mode := range []string{"missing-ipv6", "source-inside-allowlist", "denied-allowed-tuple", "missing-flow", "missing-recovery-source", "wrong-destination-host", "ssh-wrong-port", "ssh-wrong-address", "non-container-east-west"} {
		t.Run(mode, func(t *testing.T) {
			policy := in
			p := local
			p.Cases = append([]generated.AccessProbeCase(nil), local.Cases...)
			r := remote
			switch mode {
			case "missing-ipv6":
				policy.Interfaces = append([]generated.AccessInterface(nil), in.Interfaces...)
				policy.Interfaces[0].IPv6Enabled = true
			case "source-inside-allowlist":
				r.Source.Address = "192.0.2.3"
			case "denied-allowed-tuple":
				p.Cases[5].Destination.Port = 22
			case "missing-flow":
				policy.HostFlows = []generated.AccessFlow{{Protocol: "tcp", SourcePrefix: "192.0.2.0/24", DestinationPrefix: "192.0.2.2/32", Port: 443, Interface: "eth0"}}
			case "missing-recovery-source":
				policy.RecoverySourcePrefixes = []string{"192.0.2.10/32"}
			case "ssh-wrong-port":
				p.Cases[0].Destination.Port = 2223
			case "ssh-wrong-address":
				p.Cases[0].Destination.Address = "192.0.2.99"
			case "non-container-east-west":
				c := p.Cases[5]
				c.Kind = "container-east-west"
				p.Cases = append(p.Cases, c)
			case "wrong-destination-host":
				p.Cases[4].Destination.HostID = "unrelated"
			}
			if validateProbePolicy(policy, []generated.AccessProbeInput{p, r}) == nil {
				t.Fatal("unproved policy accepted")
			}
		})
	}
}

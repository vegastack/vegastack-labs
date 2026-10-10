package debianaccess

import (
	"reflect"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestContainerFirewallUsesOriginalConnectionTuple(t *testing.T) {
	in := validInput(t)
	for _, tc := range []struct{ family, src, published, direct string }{
		{"ipv4", "192.0.2.1/32", "192.0.2.2/32", "203.0.113.11/32"},
		{"ipv6", "2001:db8::1/128", "2001:db8::2/128", "2001:db8:1::11/128"},
	} {
		t.Run(tc.family, func(t *testing.T) {
			in.ContainerFlows = []generated.AccessFlow{
				{Interface: "eth0", SourcePrefix: tc.src, DestinationPrefix: tc.published, Protocol: "tcp", Port: 18080},
				{Interface: "eth0", SourcePrefix: tc.src, DestinationPrefix: tc.direct, Protocol: "udp", Port: 18081},
			}
			in.HostFlows = []generated.AccessFlow{in.ContainerFlows[0]}
			rules, err := DesiredFirewallRules(in, tc.family, "VSK-ACCESS-DKR")
			if err != nil {
				t.Fatal(err)
			}
			for i, flow := range in.ContainerFlows {
				want := []string{"-i", "eth0", "-p", flow.Protocol, "-m", "conntrack", "--ctorigsrc", tc.src, "--ctorigdst", flow.DestinationPrefix, "--ctorigdstport", []string{"18080", "18081"}[i], "--ctdir", "ORIGINAL", "-j", "RETURN"}
				if !reflect.DeepEqual(rules[i+1], want) || !validOwnedRule(rules[i+1]) {
					t.Fatalf("original tuple missing: %v", rules[i+1])
				}
			}
			host, err := DesiredFirewallRules(in, tc.family, "VSK-ACCESS-IN")
			if err != nil {
				t.Fatal(err)
			}
			joined := ""
			for _, r := range host {
				joined += strings.Join(r, " ") + "\n"
			}
			if strings.Contains(joined, "--ctorig") || !strings.Contains(joined, "-d "+tc.published+" -p tcp --dport 18080 -j ACCEPT") {
				t.Fatalf("host semantics changed: %s", joined)
			}
		})
	}
}

func TestOriginalConnectionRuleSaveNormalizationAndRefusal(t *testing.T) {
	want := []string{"-i", "eth0", "-p", "tcp", "-m", "conntrack", "--ctorigsrc", "192.0.2.1/32", "--ctorigdst", "192.0.2.2/32", "--ctorigdstport", "18080", "--ctdir", "ORIGINAL", "-j", "RETURN"}
	saved := []string{"-i", "eth0", "-p", "tcp", "-m", "tcp", "-m", "conntrack", "--ctdir", "ORIGINAL", "--ctorigdst", "192.0.2.2", "--ctorigsrc", "192.0.2.1", "--ctorigdstport", "18080", "-j", "RETURN"}
	got := normalizeOwnedRule(saved)
	if !reflect.DeepEqual(got, want) || !validOwnedRule(got) {
		t.Fatalf("iptables-save tuple did not normalize: %v", got)
	}
	zero := append([]string{}, want...)
	zero[7] = "0.0.0.0/0"
	if !validOwnedRule(normalizeOwnedRule(zero)) {
		t.Fatal("explicit original source prefix lost")
	}
	established := normalizeOwnedRule([]string{"-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "RETURN"})
	if !validOwnedRule(established) || established[3] != "ESTABLISHED,RELATED" {
		t.Fatalf("existing state rule changed: %v", established)
	}
	for name, mutate := range map[string]func([]string) []string{
		"reply":             func(r []string) []string { r[13] = "REPLY"; return r },
		"missing-direction": func(r []string) []string { return append(r[:12], r[14:]...) },
		"missing-source":    func(r []string) []string { return append(r[:6], r[8:]...) },
		"invalid-prefix":    func(r []string) []string { r[9] = "not-an-address"; return r },
		"invalid-port":      func(r []string) []string { r[11] = "0"; return r },
		"range-port":        func(r []string) []string { r[11] = "80:81"; return r },
		"wrong-module":      func(r []string) []string { r[5] = "tcp"; return r },
		"state-default": func(r []string) []string {
			return append(append(append([]string{}, r[:14]...), "--ctstate", "NEW"), r[14:]...)
		},
		"unknown-original-option": func(r []string) []string {
			return append(append(append([]string{}, r[:14]...), "--ctorigsrcport", "12345"), r[14:]...)
		},
		"duplicate-direction": func(r []string) []string {
			return append(append(append([]string{}, r[:14]...), "--ctdir", "ORIGINAL"), r[14:]...)
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := mutate(append([]string{}, want...))
			if validOwnedRule(normalizeOwnedRule(r)) {
				t.Fatalf("unsafe original tuple accepted: %v", r)
			}
		})
	}
}

//go:build linux

package cijobrunner

import (
	"bufio"
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"golang.org/x/sys/unix"
)

func TestEgressRulesRejectBypassesAndDrift(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		first, chain := ExpectedEgressRules(505, "1.1.1.1", v6)
		output := "-P OUTPUT ACCEPT\n" + first
		if checkEgressRules(output, chain, first, chain) != nil {
			t.Fatal("exact rules denied")
		}
		for name, mut := range map[string][2]string{
			"prior accept":       {"-P OUTPUT ACCEPT\n-A OUTPUT -j ACCEPT\n" + first, chain},
			"wrong UID":          {strings.ReplaceAll(output, "505", "506"), chain},
			"missing final deny": {output, strings.TrimSuffix(chain, "\n-A "+egressChain+" -j DROP")},
			"extra accept":       {output, chain + "\n-A " + egressChain + " -j ACCEPT"},
			"established bypass": {output, strings.Replace(chain, "-N "+egressChain, "-N "+egressChain+"\n-A "+egressChain+" -m conntrack --ctstate ESTABLISHED -j ACCEPT", 1)},
		} {
			t.Run(name, func(t *testing.T) {
				if checkEgressRules(mut[0], mut[1], first, chain) == nil {
					t.Fatal("drift accepted")
				}
			})
		}
	}
	// Special-use destinations must be denied before any public allow.
	_, chain := ExpectedEgressRules(505, "1.1.1.1", false)
	for _, ip := range []string{"10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.169.254", "172.16.0.1", "192.168.1.1", "198.18.0.1"} {
		address := netip.MustParseAddr(ip)
		if !deniedAddress(address) {
			t.Fatal("required deny missing", ip)
		}
		matched := false
		for _, prefix := range deniedV4 {
			if netip.MustParsePrefix(prefix).Contains(address) {
				pos := strings.Index(chain, "-d "+prefix+" -j DROP")
				if pos < 0 || pos > strings.Index(chain, "--dport 443 -j ACCEPT") {
					t.Fatal("deny ordering", ip)
				}
				matched = true
			}
		}
		if !matched {
			t.Fatal(ip)
		}
	}
}
func TestNetworkPolicyBindsResolverAndWitnesses(t *testing.T) {
	policy := NetworkPolicy{Resolver: "1.1.1.1", PublicWitness: "93.184.216.34:443", DeniedWitnesses: []string{"198.18.0.2:8080"}, RootlessKitPID: 42}
	p := RuntimeProfile{DNSResolver: policy.Resolver, NetworkEvidenceDigest: hostaction.Digest(policy)}
	if !validNetworkPolicy(policy, p) {
		t.Fatal("protected numeric policy rejected")
	}
	for _, mut := range []func(*NetworkPolicy){func(p *NetworkPolicy) { p.Resolver = "127.0.0.1" }, func(p *NetworkPolicy) { p.PublicWitness = "example.com:443" }, func(p *NetworkPolicy) { p.DeniedWitnesses = []string{"8.8.8.8:443"} }, func(p *NetworkPolicy) { p.DeniedWitnesses = nil }, func(p *NetworkPolicy) { p.RootlessKitPID = 0 }} {
		m := policy
		mut(&m)
		q := p
		q.NetworkEvidenceDigest = hostaction.Digest(m)
		q.DNSResolver = m.Resolver
		if validNetworkPolicy(m, q) {
			t.Fatal("unsafe policy accepted", m)
		}
	}
	q := p
	q.NetworkEvidenceDigest = "sha256:" + strings.Repeat("0", 64)
	if validNetworkPolicy(policy, q) {
		t.Fatal("policy drift accepted")
	}
}
func TestNativeArchitectureAndDNS(t *testing.T) {
	p := RuntimeProfile{NetworkID: "owned", DNSResolver: "1.1.1.1"}
	a := strings.Join(baseArgs(p), " ")
	if !strings.Contains(a, "--platform linux/"+runtime.GOARCH) || !strings.Contains(a, "--dns 1.1.1.1") {
		t.Fatal(a)
	}
	p.Offline = true
	if strings.Contains(strings.Join(baseArgs(p), " "), "--dns") {
		t.Fatal("offline DNS configured")
	}
}
func TestPrivateNetworkChannelDenyAndReplay(t *testing.T) {
	pair, e := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	parent := os.NewFile(uintptr(pair[0]), "parent")
	child := os.NewFile(uintptr(pair[1]), "child")
	defer parent.Close()
	defer child.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go serveNetwork(ctx, parent, NativeConfig{}) // Missing actual policy MUST deny, never caller asserted pass.
	c := networkClient{file: child, reader: bufio.NewReader(child)}
	if c.Check(ctx, RuntimeProfile{}, NetworkCheck{}) == nil {
		t.Fatal("absent protected policy passed")
	}
	c.next = 2
	if c.Check(ctx, RuntimeProfile{}, NetworkCheck{}) == nil {
		t.Fatal("replay passed")
	}
}

// Explicit root-only public/synthetic fixture. The coordinator owns VM/rules,
// witness configuration and cleanup; no environment can install rules here.
func TestNativeProtectedNetwork(t *testing.T) {
	path := os.Getenv("VSK_CI_NETWORK_NATIVE_CONFIG")
	if path == "" {
		t.Skip("explicit synthetic native configuration required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root parent required")
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	var c NativeConfig
	if decodeFrame(context.Background(), raw, &c) != nil {
		t.Fatal("invalid fixture configuration")
	}
	check := NetworkCheck{}
	if raw := os.Getenv("VSK_CI_NETWORK_PAYLOAD"); raw != "" {
		if json.Unmarshal([]byte(raw), &check) != nil {
			t.Fatal("invalid payload")
		}
	}
	if e := (rootNetworkVerifier{c}).Check(context.Background(), c.Profile, check); e != nil {
		t.Fatal("current native policy denied", e)
	}
	if origin := os.Getenv("VSK_CI_NETWORK_DEPLOYMENT_ORIGIN"); origin != "" {
		if e := (rootNetworkVerifier{c}).CheckDeployment(context.Background(), c.Profile, check, origin); e != nil {
			t.Fatal("current exact deployment origin denied", e)
		}
	}
}

func TestConnectedPublicLANBlocks(t *testing.T) {
	if !connectedRoutesDenied(`[{"dst":"default","gateway":"192.168.5.2"},{"dst":"192.168.5.0/24","scope":"link"},{"dst":"192.168.5.2","scope":"link"},{"dst":"198.18.0.0/24","scope":"link"}]`) {
		t.Fatal("private/test LAN denied")
	}
	for _, raw := range []string{`[{"dst":"8.8.8.8","scope":"link"}]`, `[{"dst":"8.8.8.0/24","scope":"link"}]`, `[{"dst":"default","scope":"link"}]`, `[]`, `garbage`, `[{"dst":"0.0.0.0/0","scope":"link"}]`} {
		if connectedRoutesDenied(raw) {
			t.Fatal("uncovered connected route accepted", raw)
		}
	}
}

func TestActiveCrossBridgeSiblingBlocks(t *testing.T) {
	id := strings.Repeat("a", 64)
	other := strings.Repeat("b", 64)
	if !solePayload("", "") || !solePayload(id, id) {
		t.Fatal("exclusive daemon rejected")
	}
	for _, raw := range []string{id + "\n" + other, other, "", id + "\n" + id} {
		if solePayload(raw, id) {
			t.Fatal("nonexclusive daemon accepted")
		}
	}
	if solePayload(other, "") {
		t.Fatal("preexisting sibling accepted")
	}
}

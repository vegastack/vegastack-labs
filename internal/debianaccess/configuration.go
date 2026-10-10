package debianaccess

import (
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

// DesiredFiles maps finite resource IDs to exact owned paths. No input supplies a path.
func DesiredFiles(input generated.DebianAccessInput) (map[string][]byte, error) {
	out := map[string][]byte{}
	users := append([]string(nil), input.SSHUsers...)
	sort.Strings(users)
	for _, u := range users {
		if !accessName.MatchString(u) || u == "root" {
			return nil, errAccess
		}
	}
	if len(users) == 0 {
		return nil, errAccess
	}
	ssh := "# Owned by the acknowledged VegaStack Debian access profile.\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\nPermitEmptyPasswords no\nPermitRootLogin no\nAuthorizedKeysFile /etc/vsk-labs/authorized_keys/%u\nAllowUsers " + strings.Join(users, " ") + "\n"
	// Service-root exception is rendered separately after the declared source/key checks.
	if len(input.PrivilegedServiceKeys) > 0 {
		ssh = strings.Replace(ssh, "AllowUsers "+strings.Join(users, " "), "AllowUsers "+strings.Join(users, " ")+" root", 1)
		ssh += "Match User root\n    PermitRootLogin prohibit-password\n    AuthorizedKeysFile /etc/vsk-labs/service_authorized_keys/root\n    AuthenticationMethods publickey\n    PermitTTY no\n    AllowTcpForwarding no\n    AllowAgentForwarding no\n    X11Forwarding no\nMatch all\n"
	}
	out["etc/ssh/sshd_config.d/70-vsk-access.conf"] = []byte(ssh)
	for _, a := range input.Accounts {
		if !accessName.MatchString(a.Name) || a.Name == "root" {
			return nil, errAccess
		}
		keys := append([]string(nil), a.PublicKeys...)
		sort.Strings(keys)
		for _, k := range keys {
			if strings.ContainsAny(k, "\r\n") {
				return nil, errAccess
			}
		}
		if a.Role == "automation" {
			for i := range keys {
				keys[i] = "restrict " + keys[i]
			}
		}
		out["etc/vsk-labs/authorized_keys/"+a.Name] = []byte(strings.Join(keys, "\n") + "\n")
	}
	if len(input.PrivilegedServiceKeys) > 0 {
		var keys []string
		for _, k := range input.PrivilegedServiceKeys {
			if strings.ContainsAny(k.PublicKey, "\r\n") || len(k.SourcePrefixes) == 0 {
				return nil, errAccess
			}
			prefixes := append([]string(nil), k.SourcePrefixes...)
			sort.Strings(prefixes)
			for _, p := range prefixes {
				n, e := netip.ParsePrefix(p)
				if e != nil || n.Masked().String() != p {
					return nil, errAccess
				}
			}
			keys = append(keys, `restrict,from="`+strings.Join(prefixes, ",")+`" `+k.PublicKey)
		}
		sort.Strings(keys)
		out["etc/vsk-labs/service_authorized_keys/root"] = []byte(strings.Join(keys, "\n") + "\n")
	}
	return out, nil
}
func resourceForFile(p string) string {
	if p == "etc/vsk-labs/service_authorized_keys/root" {
		return "service-root-keys"
	}
	if p == "etc/ssh/sshd_config.d/70-vsk-access.conf" {
		return "ssh-config"
	}
	return "authorized-keys:" + strings.TrimPrefix(p, "etc/vsk-labs/authorized_keys/")
}

// DesiredFirewallRules returns only argv tokens for our two owned chains.
// Caller selects the fixed iptables-nft/ip6tables-nft executable, never a shell.
func DesiredFirewallRules(input generated.DebianAccessInput, family, chain string) ([][]string, error) {
	if family != "ipv4" && family != "ipv6" {
		return nil, errAccess
	}
	if chain != "VSK-ACCESS-IN" && chain != "VSK-ACCESS-DKR" {
		return nil, errAccess
	}
	is4 := family == "ipv4"
	rules := [][]string{{"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "RETURN"}}
	if chain == "VSK-ACCESS-IN" {
		rules = append(rules, []string{"-i", "lo", "-j", "RETURN"})
		if !is4 {
			rules = append(rules, []string{"-p", "ipv6-icmp", "-j", "RETURN"})
		}
		for _, prefix := range append(append([]string(nil), input.SSHSourcePrefixes...), input.RecoverySourcePrefixes...) {
			p, e := netip.ParsePrefix(prefix)
			if e != nil {
				return nil, errAccess
			}
			if p.Addr().Is4() != is4 {
				continue
			}
			for _, iface := range input.Interfaces {
				rules = append(rules, []string{"-i", iface.Name, "-s", prefix, "-p", "tcp", "--dport", "22", "-j", "RETURN"})
			}
		}
	}
	flows := input.HostFlows
	if chain == "VSK-ACCESS-DKR" {
		flows = input.ContainerFlows
	}
	for _, f := range flows {
		s, e := netip.ParsePrefix(f.SourcePrefix)
		d, e2 := netip.ParsePrefix(f.DestinationPrefix)
		if e != nil || e2 != nil || s.Addr().Is4() != d.Addr().Is4() || f.Port < 1 || f.Port > 65535 || (f.Protocol != "tcp" && f.Protocol != "udp") {
			return nil, errAccess
		}
		if s.Addr().Is4() != is4 {
			continue
		}
		if chain == "VSK-ACCESS-DKR" {
			// DOCKER-USER sees packets after DNAT. Policy/probes name the original
			// connection tuple, which is also unchanged for direct container traffic.
			// https://docs.docker.com/engine/network/firewall-iptables/#match-the-original-ip-and-ports-for-requests
			rules = append(rules, []string{"-i", f.Interface, "-p", f.Protocol, "-m", "conntrack", "--ctorigsrc", f.SourcePrefix, "--ctorigdst", f.DestinationPrefix, "--ctorigdstport", fmt.Sprint(f.Port), "--ctdir", "ORIGINAL", "-j", "RETURN"})
		} else {
			rules = append(rules, []string{"-i", f.Interface, "-s", f.SourcePrefix, "-d", f.DestinationPrefix, "-p", f.Protocol, "--dport", fmt.Sprint(f.Port), "-j", "RETURN"})
		}
	}
	// Limit default drops to declared ingress interfaces. Unknown interfaces remain
	// observable admission failures, never permission to alter unrelated networking.
	for _, iface := range input.Interfaces {
		rules = append(rules, []string{"-i", iface.Name, "-j", "DROP"})
	}
	if chain == "VSK-ACCESS-IN" {
		for _, rule := range rules {
			if rule[len(rule)-1] == "RETURN" {
				rule[len(rule)-1] = "ACCEPT"
			}
		}
	}
	rules = append(rules, []string{"-j", "RETURN"})
	for i := range rules {
		rules[i] = normalizeOwnedRule(rules[i])
	}
	return rules, nil
}

func normalizeOwnedRule(rule []string) []string {
	out := []string{}
	for i := 0; i < len(rule); i++ {
		if i+1 < len(rule) {
			v := rule[i+1]
			if rule[i] == "-m" && (v == "tcp" || v == "udp") {
				i++
				continue
			}
			if rule[i] == "--ctstate" {
				states := strings.Split(v, ",")
				sort.Strings(states)
				out = append(out, rule[i], strings.Join(states, ","))
				i++
				continue
			}
			if rule[i] == "-s" || rule[i] == "-d" || rule[i] == "--ctorigsrc" || rule[i] == "--ctorigdst" {
				p, e := netip.ParsePrefix(v)
				if e != nil {
					if a, err := netip.ParseAddr(v); err == nil {
						bits := 128
						if a.Is4() {
							bits = 32
						}
						p = netip.PrefixFrom(a, bits)
						e = nil
					}
				}
				if e == nil {
					if p.Bits() == 0 && (rule[i] == "-s" || rule[i] == "-d") {
						i++
						continue
					}
					out = append(out, rule[i], p.Masked().String())
					i++
					continue
				}
			}
		}
		out = append(out, rule[i])
	}
	ordered := []string{}
	for _, option := range []string{"--ctorigsrc", "--ctorigdst", "--ctorigdstport", "--ctdir"} {
		for i := 0; i+1 < len(out); i += 2 {
			if out[i] == option {
				ordered = append(ordered, out[i:i+2]...)
			}
		}
	}
	if len(ordered) > 0 && len(out)%2 == 0 && len(out) >= 2 && out[len(out)-2] == "-j" {
		base := []string{}
		for i := 0; i < len(out)-2; i += 2 {
			if out[i] != "--ctorigsrc" && out[i] != "--ctorigdst" && out[i] != "--ctorigdstport" && out[i] != "--ctdir" {
				base = append(base, out[i:i+2]...)
			}
		}
		out = append(append(base, ordered...), out[len(out)-2:]...)
	}
	return out
}

func validOwnedRule(rule []string) bool {
	if len(rule) < 2 || len(rule) > 24 {
		return false
	}
	for _, token := range rule {
		if token == "" || strings.ContainsAny(token, " \t\r\n\"'\\;") {
			return false
		}
	}
	// Only values for the compiled option vocabulary are accepted. No chain mutation,
	// jump to a user-selected chain, extension command or restore directive is possible.
	options := map[string]bool{"-i": true, "-s": true, "-d": true, "-p": true, "--dport": true, "--ctstate": true, "-m": true, "-j": true, "--ctorigsrc": true, "--ctorigdst": true, "--ctorigdstport": true, "--ctdir": true}
	seen := map[string]bool{}
	original := false
	for i := 0; i < len(rule); i += 2 {
		if i+1 >= len(rule) || !options[rule[i]] {
			return false
		}
		v := rule[i+1]
		if seen[rule[i]] && rule[i] != "-m" {
			return false
		}
		seen[rule[i]] = true
		if strings.HasPrefix(rule[i], "--ctorig") {
			original = true
			if rule[i] == "--ctorigdstport" {
				port, err := strconv.Atoi(v)
				if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != v {
					return false
				}
			} else if _, err := netip.ParsePrefix(v); err != nil {
				return false
			}
		}
		if rule[i] == "--ctdir" && v != "ORIGINAL" {
			return false
		}
		if rule[i] == "-j" && v != "ACCEPT" && v != "RETURN" && v != "DROP" {
			return false
		}
		if rule[i] == "-m" && v != "conntrack" && v != "tcp" && v != "udp" {
			return false
		}
	}
	if original || seen["--ctdir"] {
		if !seen["--ctorigsrc"] || !seen["--ctorigdst"] || !seen["--ctorigdstport"] || !seen["--ctdir"] || seen["--ctstate"] || seen["-s"] || seen["-d"] || seen["--dport"] {
			return false
		}
		module, protocol := "", ""
		for i := 0; i < len(rule); i += 2 {
			if rule[i] == "-m" {
				module = rule[i+1]
			}
			if rule[i] == "-p" {
				protocol = rule[i+1]
			}
		}
		if module != "conntrack" || (protocol != "tcp" && protocol != "udp") {
			return false
		}
	}
	return rule[len(rule)-2] == "-j"
}

func desiredFileMode(p string) os.FileMode {
	if p == "etc/vsk-labs/service_authorized_keys/root" {
		return 0600
	}
	return 0644
}

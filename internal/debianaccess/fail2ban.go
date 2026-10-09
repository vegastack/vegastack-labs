package debianaccess

import (
	"net/netip"
	"strings"
)

// The sole permitted rule before our INPUT jump can only discard SSH traffic.
// Its complete target chain is validated first; it cannot grant access or jump
// into another owner's chain.
func validFail2banPrefix(raw, family string) bool {
	present := false
	returns := 0
	refs := 0
	for _, line := range strings.Split(raw, "\n") {
		f := strings.Fields(line)
		if len(f) == 3 && f[0] == "-N" && f[1] == "f2b-vsk-sshd" {
			return false
		}
		if len(f) == 2 && f[0] == "-N" && f[1] == "f2b-vsk-sshd" {
			present = true
		}
		if len(f) >= 2 && f[0] == "-A" && f[1] == "f2b-vsk-sshd" {
			if len(f) == 4 && f[2] == "-j" && f[3] == "RETURN" {
				returns++
				continue
			}
			if len(f) != 6 || f[2] != "-s" || f[4] != "-j" || f[5] != "DROP" || returns > 0 {
				return false
			}
			a, e := netip.ParsePrefix(f[3])
			if e != nil {
				v, e := netip.ParseAddr(f[3])
				if e != nil {
					return false
				}
				a = netip.PrefixFrom(v, v.BitLen())
			}
			if a.Bits() != a.Addr().BitLen() || (family == "ipv4") != a.Addr().Is4() {
				return false
			}
		}
		for i := 2; i < len(f)-1; i++ {
			if (f[i] == "-j" || f[i] == "-g") && f[i+1] == "f2b-vsk-sshd" {
				if strings.Join(f, " ") != "-A INPUT -p tcp -m tcp --dport 22 -j f2b-vsk-sshd" {
					return false
				}
				refs++
			}
		}
	}
	return present && returns == 1 && refs == 1
}

// ValidateSSHBanPrefix exposes only a read-only finite parser for the baseline owner.
func ValidateSSHBanPrefix(raw, family string) bool { return validFail2banPrefix(raw, family) }

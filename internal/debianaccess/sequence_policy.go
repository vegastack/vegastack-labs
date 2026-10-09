package debianaccess

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"net/netip"
	"strconv"
	"strings"
)

// Probe coverage is derived from the approved policy, never from case labels alone.
func validateProbePolicy(in generated.DebianAccessInput, probes []generated.AccessProbeInput) error {
	families := map[bool]bool{}
	for _, iface := range in.Interfaces {
		for _, raw := range iface.Addresses {
			a, e := netip.ParseAddr(raw)
			if e != nil {
				return errInput
			}
			families[a.Is6()] = true
		}
		if iface.IPv6Enabled {
			families[true] = true
		}
	}
	contains := func(prefixes []string, a netip.Addr) bool {
		for _, raw := range prefixes {
			p, e := netip.ParsePrefix(raw)
			if e == nil && p.Contains(a) {
				return true
			}
		}
		return false
	}
	covers := map[string]bool{}
	flowCovered := map[string]bool{}
	matchFlow := func(f generated.AccessFlow, src, dst netip.Addr, c generated.AccessProbeCase, container bool) bool {
		sp, e := netip.ParsePrefix(f.SourcePrefix)
		if e != nil {
			return false
		}
		dp, e := netip.ParsePrefix(f.DestinationPrefix)
		if e != nil || !sp.Contains(src) || !dp.Contains(dst) || f.Port != c.Destination.Port || f.Protocol != c.Destination.Protocol {
			return false
		}
		for _, iface := range in.Interfaces {
			if iface.Name != f.Interface {
				continue
			}
			if container {
				return true
			}
			for _, address := range iface.Addresses {
				if address == dst.String() {
					return true
				}
			}
		}
		return false
	}
	for _, p := range probes {
		src, e := netip.ParseAddr(p.Source.Address)
		if e != nil || p.Source.Family != map[bool]string{false: "ipv4", true: "ipv6"}[src.Is6()] {
			return errInput
		}
		for _, c := range p.Cases {
			dst, e := netip.ParseAddr(c.Destination.Address)
			if e != nil || dst.Is6() != src.Is6() || c.Destination.HostID != in.HostID || c.Destination.IdentityDigest != in.HostIdentityDigest || !families[src.Is6()] {
				return errInput
			}
			family := "4"
			if src.Is6() {
				family = "6"
			}
			if strings.HasPrefix(c.Kind, "ssh-") {
				if c.Destination.Protocol != "tcp" {
					return errInput
				}
				allowed := contains(in.SSHSourcePrefixes, src)
				if c.Kind == "ssh-source" {
					if allowed || c.Expected != "denied" {
						return errInput
					}
				} else {
					if !allowed {
						return errInput
					}
					if (c.Kind == "ssh-admin") != (c.Expected == "allowed") {
						return errInput
					}
				}
				covers[c.Kind+":"+family] = true
				if c.Kind == "ssh-admin" {
					for _, prefix := range append(append([]string{}, in.SSHSourcePrefixes...), in.RecoverySourcePrefixes...) {
						if contains([]string{prefix}, src) {
							covers["prefix:"+prefix] = true
						}
					}
				}
				continue
			}
			container := strings.HasPrefix(c.Kind, "container-")
			flows := in.HostFlows
			if container {
				flows = in.ContainerFlows
			}
			matched := false
			for i, f := range flows {
				if matchFlow(f, src, dst, c, container) {
					matched = true
					if c.Expected == "allowed" {
						flowCovered[map[bool]string{false: "host", true: "container"}[container]+":"+strconv.Itoa(i)] = true
					}
				}
			}
			// SSH is the sole implicit host allow rule, fixed by the owned baseline.
			if !container && c.Destination.Protocol == "tcp" && c.Destination.Port == 22 && contains(in.SSHSourcePrefixes, src) {
				matched = true
			}
			if (c.Expected == "allowed") != matched {
				return errInput
			}
			covers[c.Kind+":"+c.Expected+":"+family] = true
		}
	}
	for _, prefix := range append(append([]string{}, in.SSHSourcePrefixes...), in.RecoverySourcePrefixes...) {
		if !covers["prefix:"+prefix] {
			return errInput
		}
	}
	for six := range families {
		family := "4"
		if six {
			family = "6"
		}
		for _, kind := range []string{"ssh-admin", "ssh-wrong-user", "ssh-password", "ssh-root", "ssh-source"} {
			if !covers[kind+":"+family] {
				return errInput
			}
		}
		for _, expected := range []string{"allowed", "denied"} {
			if !covers["host-flow:"+expected+":"+family] {
				return errInput
			}
		}
		if len(in.ContainerFlows) > 0 {
			for _, required := range []string{"container-published:allowed", "container-unpublished:denied", "container-east-west:allowed", "container-east-west:denied"} {
				if !covers[required+":"+family] {
					return errInput
				}
			}
		}
	}
	for i := range in.HostFlows {
		if !flowCovered["host:"+strconv.Itoa(i)] {
			return errInput
		}
	}
	for i := range in.ContainerFlows {
		if !flowCovered["container:"+strconv.Itoa(i)] {
			return errInput
		}
	}
	return nil
}

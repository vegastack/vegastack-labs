//go:build linux

package cijobrunner

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"golang.org/x/sys/unix"
)

const egressChain = "VSK-CI-EGRESS"

// NetworkPolicy is protected host configuration, never a caller qualification.
// Witnesses are explicit owned synthetic endpoints, not discovery targets.
type NetworkPolicy struct {
	Resolver        string   `json:"resolver"`
	PublicWitness   string   `json:"publicWitness"`
	DeniedWitnesses []string `json:"deniedWitnesses"`
	RootlessKitPID  int      `json:"rootlessKitPid"`
}

var deniedV4 = []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"}

func deniedAddress(a netip.Addr) bool {
	if !a.Is4() {
		return true
	}
	for _, s := range deniedV4 {
		if netip.MustParsePrefix(s).Contains(a) {
			return true
		}
	}
	return false
}
func validNetworkPolicy(p NetworkPolicy, profile RuntimeProfile) bool {
	a, e := netip.ParseAddr(p.Resolver)
	if e != nil || deniedAddress(a) || p.Resolver != profile.DNSResolver || p.RootlessKitPID < 2 || len(p.DeniedWitnesses) < 1 || len(p.DeniedWitnesses) > 8 || hostaction.Digest(p) != profile.NetworkEvidenceDigest {
		return false
	}
	ip, port, e := net.SplitHostPort(p.PublicWitness)
	pub, err := netip.ParseAddr(ip)
	if e != nil || err != nil || deniedAddress(pub) || port != "443" {
		return false
	}
	seen := map[string]bool{}
	for _, w := range p.DeniedWitnesses {
		ip, port, e := net.SplitHostPort(w)
		a, err := netip.ParseAddr(ip)
		n, pe := strconv.Atoi(port)
		if e != nil || err != nil || !a.Is4() || !deniedAddress(a) || pe != nil || n < 1 || n > 65535 || seen[w] {
			return false
		}
		seen[w] = true
	}
	return true
}

// ExpectedEgressRules is the fixed first-profile ruleset. Installation is an
// independently authorized host configuration action; this package only reads.
func ExpectedEgressRules(uid uint32, resolver string, ipv6 bool) (string, string) {
	output := "-A OUTPUT -m owner --uid-owner " + strconv.FormatUint(uint64(uid), 10) + " -j " + egressChain
	chain := []string{"-N " + egressChain}
	add := func(s string) { chain = append(chain, "-A "+egressChain+" "+s) }
	if !ipv6 {
		add("-m addrtype --dst-type LOCAL -j DROP")
		for _, cidr := range deniedV4 {
			add("-d " + cidr + " -j DROP")
		}
		for _, proto := range []string{"udp", "tcp"} {
			add("-d " + resolver + "/32 -p " + proto + " -m " + proto + " --dport 53 -j ACCEPT")
		}
		add("-p tcp -m tcp --dport 443 -j ACCEPT")
	}
	add("-j DROP")
	return output, strings.Join(chain, "\n")
}
func checkEgressRules(output, chain, wantOutput, wantChain string) error {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	// The exact UID jump must precede every potentially accepting OUTPUT rule.
	if len(lines) < 2 || !strings.HasPrefix(lines[0], "-P OUTPUT ") || lines[1] != wantOutput || strings.TrimSpace(chain) != wantChain {
		return ErrBlocked
	}
	return nil
}

type rootNetworkVerifier struct{ config NativeConfig }

func (v rootNetworkVerifier) command(ctx context.Context, docker bool, args ...string) (string, error) {
	path := "/usr/sbin/iptables-nft"
	if !docker {
		path = args[0]
		args = args[1:]
	}
	if docker {
		path = v.config.Docker.ExecutablePath
		args = append([]string{"--host", "unix://" + v.config.Docker.SocketPath}, args...)
	}
	// Every executable is a fixed protected host path; never run an action-supplied command.
	st, e := os.Stat(path)
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0022 != 0 || st.Sys().(*syscall.Stat_t).Uid != 0 {
		return "", ErrBlocked
	}
	c := exec.CommandContext(ctx, path, args...)
	c.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "DOCKER_CONFIG=/nonexistent"}
	c.Stderr = io.Discard
	if docker {
		c.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: v.config.Profile.DaemonUID, Gid: v.config.DaemonGID, Groups: []uint32{}}}
	}
	b := &capBuffer{max: 64 << 10}
	c.Stdout = b
	if c.Run() != nil {
		return "", ErrBlocked
	}
	return strings.TrimSpace(b.String()), nil
}

// The daemon socket peer must descend from this measured RootlessKit parent.
// A matching unrelated command line is insufficient.
func daemonDescendsFrom(socket string, uid uint32, parent int) bool {
	conn, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: socket, Net: "unix"})
	if e != nil {
		return false
	}
	defer conn.Close()
	raw, e := conn.SyscallConn()
	if e != nil {
		return false
	}
	var peer *unix.Ucred
	var pe error
	if raw.Control(func(fd uintptr) { peer, pe = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }) != nil || pe != nil || peer == nil || peer.Uid != uid {
		return false
	}
	pid := int(peer.Pid)
	for n := 0; n < 32 && pid > 1; n++ {
		if pid == parent {
			return true
		}
		b, e := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
		if e != nil {
			return false
		}
		end := strings.LastIndexByte(string(b), ')')
		if end < 0 {
			return false
		}
		fields := strings.Fields(string(b)[end+1:])
		if len(fields) < 2 {
			return false
		}
		pid, e = strconv.Atoi(fields[1])
		if e != nil {
			return false
		}
	}
	return false
}

func (v rootNetworkVerifier) Check(ctx context.Context, p RuntimeProfile, c NetworkCheck) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if os.Geteuid() != 0 || p != v.config.Profile || v.config.Network == nil || !validNetworkPolicy(*v.config.Network, p) {
		return ErrBlocked
	}
	policy := *v.config.Network
	if !daemonDescendsFrom(v.config.Docker.SocketPath, p.DaemonUID, policy.RootlessKitPID) {
		return ErrBlocked
	}
	// Verify the measured user-mode driver and disabled host-loopback on the actual daemon parent.
	raw, e := os.ReadFile("/proc/" + strconv.Itoa(policy.RootlessKitPID) + "/cmdline")
	if e != nil {
		return ErrBlocked
	}
	argv := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
	netOK, loopOK := false, false
	for _, arg := range argv {
		netOK = netOK || arg == "--net=gvisor-tap-vsock"
		loopOK = loopOK || arg == "--disable-host-loopback"
	}
	st, e := os.Stat("/proc/" + strconv.Itoa(policy.RootlessKitPID))
	if e != nil || st.Sys().(*syscall.Stat_t).Uid != p.DaemonUID || !netOK || !loopOK {
		return ErrBlocked
	}
	if v.checkRules(ctx, p) != nil || v.checkConnectedRoutes(ctx) != nil {
		return ErrBlocked
	}

	active, e := v.command(ctx, true, "ps", "--quiet", "--no-trunc")
	if e != nil || !solePayload(active, c.ContainerID) {
		return ErrBlocked
	}
	rawNet, e := v.command(ctx, true, "network", "inspect", p.NetworkID)
	if e != nil {
		return e
	}
	var networks []struct {
		ID           string `json:"Id"`
		Name, Driver string
		EnableIPv6   bool
		Options      map[string]string
		Containers   map[string]struct{ Name string }
	}
	if json.Unmarshal([]byte(rawNet), &networks) != nil || len(networks) != 1 {
		return ErrBlocked
	}
	n := networks[0]
	if n.Driver != "bridge" || n.Name != p.NetworkID || n.EnableIPv6 || n.Options["com.docker.network.bridge.enable_icc"] != "false" {
		return ErrBlocked
	}
	if c.ContainerID == "" {
		if c.InitPID != 0 || len(n.Containers) != 0 {
			return ErrBlocked
		}
		return nil
	}
	if !dockerID(c.ContainerID) || c.InitPID < 2 || len(n.Containers) != 1 {
		return ErrBlocked
	}
	if _, ok := n.Containers[c.ContainerID]; !ok {
		return ErrBlocked
	}
	rawContainer, e := v.command(ctx, true, "inspect", c.ContainerID)
	if e != nil {
		return e
	}
	var containers []struct {
		ID    string `json:"Id"`
		State struct {
			Pid     int
			Running bool
		}
		HostConfig struct {
			NetworkMode string
			Dns         []string
		}
	}
	if json.Unmarshal([]byte(rawContainer), &containers) != nil || len(containers) != 1 {
		return ErrBlocked
	}
	x := containers[0]
	if x.ID != c.ContainerID || !x.State.Running || x.State.Pid != c.InitPID || x.HostConfig.NetworkMode != p.NetworkID || len(x.HostConfig.Dns) != 1 || x.HostConfig.Dns[0] != p.DNSResolver {
		return ErrBlocked
	}
	if probePayloadNetwork(ctx, c.InitPID, policy) != nil {
		return ErrBlocked
	}
	return v.checkRules(ctx, p)
}

// The first online profile deliberately admits only one running payload in its
// dedicated daemon. An active sibling on any other bridge blocks qualification.
func solePayload(raw, id string) bool {
	ids := strings.Fields(raw)
	if id == "" {
		return len(ids) == 0
	}
	return dockerID(id) && len(ids) == 1 && ids[0] == id
}

func (v rootNetworkVerifier) checkRules(ctx context.Context, p RuntimeProfile) error {
	for _, f := range []struct {
		path string
		v6   bool
	}{{"/usr/sbin/iptables-nft", false}, {"/usr/sbin/ip6tables-nft", true}} {
		out, e := v.command(ctx, false, f.path, "-w", "2", "-S", "OUTPUT")
		if e != nil {
			return e
		}
		chain, e := v.command(ctx, false, f.path, "-w", "2", "-S", egressChain)
		if e != nil {
			return e
		}
		wo, wc := ExpectedEgressRules(p.DaemonUID, p.DNSResolver, f.v6)
		if checkEgressRules(out, chain, wo, wc) != nil {
			return ErrBlocked
		}
	}
	return nil
}
func connectedRoutesDenied(raw string) bool {
	var routes []struct{ Dst, Scope string }
	if json.Unmarshal([]byte(raw), &routes) != nil || len(routes) == 0 {
		return false
	}
	for _, r := range routes {
		if r.Scope != "link" {
			continue
		}
		p, e := netip.ParsePrefix(r.Dst)
		if e != nil || !p.Addr().Is4() {
			return false
		}
		covered := false
		for _, d := range deniedV4 {
			deny := netip.MustParsePrefix(d)
			if deny.Bits() <= p.Bits() && deny.Contains(p.Masked().Addr()) {
				covered = true
			}
		}
		if !covered {
			return false
		}
	}
	return true
}
func (v rootNetworkVerifier) checkConnectedRoutes(ctx context.Context) error {
	raw, e := v.command(ctx, false, "/usr/sbin/ip", "-j", "-4", "route", "show", "table", "main")
	if e != nil || !connectedRoutesDenied(raw) {
		return ErrBlocked
	}
	return nil
}

func connectWitness(ctx context.Context, address string) error {
	d := net.Dialer{Timeout: time.Second}
	c, e := d.DialContext(ctx, "tcp4", address)
	if e == nil {
		c.Close()
	}
	return e
}
func probePayloadNetwork(ctx context.Context, pid int, p NetworkPolicy) error {
	// A denial needs a live independently reachable owned witness, not an outage.
	for _, w := range p.DeniedWitnesses {
		if connectWitness(ctx, w) != nil {
			return ErrBlocked
		}
	}
	target, e := os.Open("/proc/" + strconv.Itoa(pid) + "/ns/net")
	if e != nil {
		return ErrBlocked
	}
	defer target.Close()
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		restored := false
		defer func() {
			if restored {
				runtime.UnlockOSThread()
			}
		}()
		original, e := os.Open("/proc/thread-self/ns/net")
		if e != nil {
			done <- ErrBlocked
			return
		}
		defer original.Close()
		if unix.Setns(int(target.Fd()), unix.CLONE_NEWNET) != nil {
			restored = true
			done <- ErrBlocked
			return
		}
		result := error(nil)
		if connectWitness(ctx, p.PublicWitness) != nil {
			result = ErrBlocked
		}
		for _, w := range p.DeniedWitnesses {
			if connectWitness(ctx, w) == nil {
				result = ErrBlocked
			}
		}
		if unix.Setns(int(original.Fd()), unix.CLONE_NEWNET) != nil {
			done <- ErrBlocked
			return
		}
		restored = true
		done <- result
	}()
	select {
	case e := <-done:
		if e != nil {
			return e
		}
	case <-ctx.Done():
		return ErrBlocked
	}
	for _, w := range p.DeniedWitnesses {
		if connectWitness(ctx, w) != nil {
			return ErrBlocked
		}
	}
	return nil
}

// networkClient uses only an inherited private socket; no controller/job frame
// can fabricate the root parent's reply. The descriptor is close-on-exec.
type networkClient struct {
	file   *os.File
	reader *bufio.Reader
	next   int
}
type networkRequest struct {
	Sequence int          `json:"sequence"`
	Check    NetworkCheck `json:"check"`
}
type networkResponse struct {
	Sequence int  `json:"sequence"`
	Passed   bool `json:"passed"`
}

func (c *networkClient) Check(ctx context.Context, _ RuntimeProfile, check NetworkCheck) error {
	c.next++
	if c.next > 2 {
		return ErrBlocked
	}
	_ = c.file.SetDeadline(time.Now().Add(35 * time.Second))
	if hostaction.WriteFrame(c.file, networkRequest{c.next, check}, 4096) != nil {
		return ErrBlocked
	}
	raw, e := hostaction.ReadFrame(c.reader, 4096)
	var r networkResponse
	if e != nil || decodeFrame(ctx, raw, &r) != nil || r.Sequence != c.next || !r.Passed {
		return ErrBlocked
	}
	return nil
}
func serveNetwork(ctx context.Context, f *os.File, c NativeConfig) {
	defer f.Close()
	r := bufio.NewReader(f)
	v := rootNetworkVerifier{c}
	for seq := 1; seq <= 2; seq++ {
		_ = f.SetDeadline(time.Now().Add(time.Hour))
		raw, e := hostaction.ReadFrame(r, 4096)
		var q networkRequest
		if e != nil || decodeFrame(ctx, raw, &q) != nil || q.Sequence != seq || (seq == 1 && q.Check.ContainerID != "") || (seq == 2 && q.Check.ContainerID == "") {
			return
		}
		passed := v.Check(ctx, c.Profile, q.Check) == nil
		if hostaction.WriteFrame(f, networkResponse{seq, passed}, 4096) != nil || !passed {
			return
		}
	}
}

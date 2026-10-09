//go:build linux

package debianaccess

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/strictjson"
	"golang.org/x/sys/unix"
)

type nativeSourceResolver struct{}

func NewNativeSourceResolver() SourceContextResolver { return nativeSourceResolver{} }
func (nativeSourceResolver) WithSource(ctx context.Context, source generated.AccessProbeSource, tuples []generated.AccessProbeTuple, fn func(SourceIdentity) error) error {
	if ctx == nil || ctx.Err() != nil || fn == nil {
		return errProbe
	}
	records, err := ReadPreparedProbeContexts()
	if err != nil {
		return err
	}
	var selected *PreparedProbeContext
	for i := range records {
		if records[i].ContextID == source.ContextID {
			if selected != nil {
				return errProbe
			}
			selected = &records[i]
		}
	}
	if selected == nil || selected.HostID != source.HostID || selected.IdentityDigest != source.IdentityDigest || selected.Kind != source.Kind || hostaction.Digest(*selected) != source.ContextDigest {
		return errProbe
	}
	record := *selected
	if len(record.ApprovedDestinations) == 0 || len(record.ApprovedDestinations) > 64 {
		return errProbe
	}
	for _, tuple := range tuples {
		found := false
		for _, allowed := range record.ApprovedDestinations {
			if samePreparedDestination(tuple, allowed) {
				found = true
				break
			}
		}
		if !found {
			return errProbe
		}
	}
	if filepath.Clean(record.NamespacePath) != record.NamespacePath {
		return errProbe
	}
	if record.Kind == "network-namespace" {
		var st unix.Stat_t
		if unix.Lstat("/run/netns", &st) != nil || st.Uid != 0 || st.Mode&0022 != 0 || st.Mode&unix.S_IFMT != unix.S_IFDIR {
			return errProbe
		}
	}
	if record.Kind == "host-network" && record.NamespacePath != "/proc/self/ns/net" {
		return errProbe
	}
	if record.Kind == "network-namespace" && (!strings.HasPrefix(record.NamespacePath, "/run/netns/") || filepath.Base(record.NamespacePath) != record.ContextID) {
		return errProbe
	}
	if record.Kind == "container" {
		if record.ProcessID <= 1 || record.NamespacePath != fmt.Sprintf("/proc/%d/ns/net", record.ProcessID) || !sameProbeProcess(record) || !sameProbeContainer(ctx, record) {
			return errProbe
		}
	}
	// A dedicated locked goroutine owns the namespace transition. If restoration
	// fails it exits while locked, causing Go to discard that OS thread.
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
			done <- errProbe
			return
		}
		defer original.Close()
		target, e := os.Open(record.NamespacePath)
		if e != nil {
			restored = true
			done <- errProbe
			return
		}
		defer target.Close()
		measured, e := namespaceDigest(target)
		if e != nil || measured != record.NamespaceDigest {
			restored = true
			done <- errProbe
			return
		}
		if record.Kind != "host-network" {
			if unix.Setns(int(target.Fd()), unix.CLONE_NEWNET) != nil {
				restored = true
				done <- errProbe
				return
			}
		}
		result := func() error {
			actual, e := os.Open("/proc/thread-self/ns/net")
			if e != nil {
				return errProbe
			}
			actualDigest, e := namespaceDigest(actual)
			actual.Close()
			if e != nil || actualDigest != measured {
				return errProbe
			}
			if ctx.Err() != nil || (record.Kind == "container" && (!sameProbeProcess(record) || !sameProbeContainer(ctx, record))) {
				return errProbe
			}
			current, e := os.Open(record.NamespacePath)
			if e != nil {
				return errProbe
			}
			fresh, e := namespaceDigest(current)
			current.Close()
			if e != nil || fresh != measured {
				return errProbe
			}
			intf, e := net.InterfaceByIndex(int(source.InterfaceIndex))
			if e != nil || intf.Name != source.Interface || intf.Flags&net.FlagUp == 0 {
				return errProbe
			}
			addresses, e := intf.Addrs()
			if e != nil {
				return errProbe
			}
			assigned := false
			for _, a := range addresses {
				ip, _, e := net.ParseCIDR(a.String())
				if e == nil && ip.Equal(net.ParseIP(source.Address)) {
					assigned = true
				}
			}
			if !assigned {
				return errProbe
			}
			route, e := currentRouteDigest()
			if e != nil || route != source.RouteDigest {
				return errProbe
			}
			// The route snapshot and actual bound socket together identify this path;
			// destinations were authorized from immutable records before helper dispatch.
			for _, tuple := range tuples {
				if net.ParseIP(tuple.Address) == nil || !probeRouteMatches(ctx, source, tuple) {
					return errProbe
				}
			}
			if e = fn(SourceIdentity{NamespaceDigest: measured, RouteDigest: route}); e != nil {
				return e
			}
			after, e := currentRouteDigest()
			if e != nil || after != route || (record.Kind == "container" && !sameProbeProcess(record)) {
				return errProbe
			}
			return nil
		}()
		if record.Kind != "host-network" && unix.Setns(int(original.Fd()), unix.CLONE_NEWNET) != nil {
			done <- errProbe
			return
		}
		restored = true
		done <- result
	}()
	// Always join the locked thread; socket deadlines observe ctx. Never abandon
	// a privileged namespace callback running after its caller has returned.
	return <-done
}
func namespaceDigest(file *os.File) (string, error) {
	var st unix.Stat_t
	if unix.Fstat(int(file.Fd()), &st) != nil {
		return "", errProbe
	}
	return hostaction.Digest(struct {
		Device uint64
		Inode  uint64
	}{uint64(st.Dev), st.Ino}), nil
}
func currentRouteDigest() (string, error) {
	var tables [][]byte
	for _, name := range []string{"/proc/thread-self/net/route", "/proc/thread-self/net/ipv6_route"} {
		f, e := os.Open(name)
		if e != nil {
			return "", errProbe
		}
		raw, e := io.ReadAll(io.LimitReader(f, 65537))
		f.Close()
		if e != nil || len(raw) > 65536 {
			return "", errProbe
		}
		canonical, e := canonicalRouteTable(raw, strings.HasSuffix(name, "ipv6_route"))
		if e != nil {
			return "", errProbe
		}
		tables = append(tables, canonical)
	}
	return hostaction.Digest(tables), nil
}
func sameProbeProcess(r PreparedProbeContext) bool {
	raw, e := os.ReadFile("/proc/" + strconv.Itoa(r.ProcessID) + "/stat")
	if e != nil || len(raw) > 8192 {
		return false
	}
	i := strings.LastIndex(string(raw), ") ")
	if i < 0 {
		return false
	}
	fields := strings.Fields(string(raw[i+2:]))
	return len(fields) > 19 && fields[19] == r.ProcessStart
}
func readProtectedProbeFile(path string, max int) ([]byte, error) {
	for current := filepath.Dir(path); ; current = filepath.Dir(current) {
		var st unix.Stat_t
		if unix.Lstat(current, &st) != nil || st.Uid != 0 || st.Mode&0022 != 0 || st.Mode&unix.S_IFMT != unix.S_IFDIR {
			return nil, errProbe
		}
		if current == "/" {
			break
		}
	}
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, errProbe
	}
	f := os.NewFile(uintptr(fd), "probe-contexts")
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Mode&0037 != 0 || st.Nlink != 1 || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, errProbe
	}
	raw, e := io.ReadAll(io.LimitReader(f, int64(max+1)))
	if e != nil || len(raw) > max {
		return nil, errProbe
	}
	return raw, nil
}

func probeRouteMatches(ctx context.Context, source generated.AccessProbeSource, tuple generated.AccessProbeTuple) bool {
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	cmd := exec.CommandContext(bounded, "/usr/sbin/ip", "-json", "route", "get", tuple.Address, "from", source.Address)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	var out probeBoundedBuffer
	out.maximum = 8192
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	if cmd.Run() != nil {
		return false
	}
	var records []struct {
		Dev  string `json:"dev"`
		Type string `json:"type"`
	}
	if json.Unmarshal(out.Bytes(), &records) != nil || len(records) != 1 {
		return false
	}
	return records[0].Dev == source.Interface && (records[0].Type == "" || records[0].Type == "unicast" || records[0].Type == "local")
}

type probeBoundedBuffer struct {
	bytes.Buffer
	maximum int
}

func (b *probeBoundedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.maximum-b.Len() {
		return 0, io.ErrShortBuffer
	}
	return b.Buffer.Write(p)
}

func canonicalRouteTable(raw []byte, ipv6 bool) ([]byte, error) {
	var rows []string
	for i, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if !ipv6 && i == 0 {
			continue
		}
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if ipv6 {
			if len(fields) != 10 {
				return nil, errProbe
			}
			fields = append(append([]string{}, fields[:6]...), fields[8:]...)
		} else {
			if len(fields) != 11 {
				return nil, errProbe
			}
			fields = append(append([]string{}, fields[:4]...), fields[6:]...)
		}
		rows = append(rows, strings.Join(fields, " "))
	}
	sort.Strings(rows)
	return []byte(strings.Join(rows, "\n")), nil
}
func sameProbeContainer(ctx context.Context, r PreparedProbeContext) bool {
	if len(r.ContainerID) != 64 || strings.Trim(r.ContainerID, "0123456789abcdef") != "" {
		return false
	}
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	cmd := exec.CommandContext(bounded, "/usr/bin/docker", "inspect", "--type", "container", "--format", "{{json .State}}", r.ContainerID)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "DOCKER_HOST=unix:///var/run/docker.sock"}
	var out probeBoundedBuffer
	out.maximum = 8192
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	if cmd.Run() != nil {
		return false
	}
	var state struct {
		Running bool
		Pid     int
	}
	return json.Unmarshal(out.Bytes(), &state) == nil && state.Running && state.Pid == r.ProcessID
}

// ReadPreparedProbeContexts reads only the fixed protected administrator mapping.
func ReadPreparedProbeContexts() ([]PreparedProbeContext, error) {
	raw, err := readProtectedProbeFile("/etc/vsk-labs/access-probe-contexts.json", 65536)
	if err != nil {
		return nil, errProbe
	}
	if strictjson.Scan(context.Background(), raw, strictjson.Limits{MaxDepth: 16}) != nil {
		return nil, errProbe
	}
	var records []PreparedProbeContext
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&records) != nil || len(records) > 32 {
		return nil, errProbe
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return nil, errProbe
	}
	seen := map[string]bool{}
	for _, record := range records {
		if record.ContextID == "" || seen[record.ContextID] || ProtectedName(record.HostID) || record.HostID == "" || record.IdentityDigest == "" {
			return nil, errProbe
		}
		seen[record.ContextID] = true
	}
	return records, nil
}

// ObservePreparedContainer measures only an exact administrator-prepared
// container. It neither lists containers nor changes their network/lifecycle.
func ObservePreparedContainer(ctx context.Context, record PreparedProbeContext) ([]generated.AccessDestinationObservation, error) {
	if ctx == nil || ctx.Err() != nil || record.Kind != "container" || record.ProcessID <= 1 || record.NamespacePath != fmt.Sprintf("/proc/%d/ns/net", record.ProcessID) || len(record.ContainerID) != 64 || strings.Trim(record.ContainerID, "0123456789abcdef") != "" || !sameProbeProcess(record) {
		return nil, errProbe
	}
	records, err := ReadPreparedProbeContexts()
	if err != nil {
		return nil, err
	}
	found := false
	for _, candidate := range records {
		if hostaction.Digest(candidate) == hostaction.Digest(record) {
			found = true
		}
	}
	if !found {
		return nil, errProbe
	}
	before, err := os.Open(record.NamespacePath)
	if err != nil {
		return nil, errProbe
	}
	namespace, err := namespaceDigest(before)
	before.Close()
	if err != nil || namespace != record.NamespaceDigest {
		return nil, errProbe
	}
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	const projection = `{"Id":{{json .Id}},"State":{{json .State}},"Networks":{{json .NetworkSettings.Networks}}}`
	cmd := exec.CommandContext(bounded, "/usr/bin/docker", "inspect", "--type", "container", "--format", projection, record.ContainerID)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "DOCKER_HOST=unix:///var/run/docker.sock"}
	var output probeBoundedBuffer
	output.maximum = 16384
	cmd.Stdout = &output
	cmd.Stderr = io.Discard
	if cmd.Run() != nil {
		return nil, errProbe
	}
	var inspected struct {
		ID    string `json:"Id"`
		State struct {
			Running bool
			Pid     int
		}
		Networks map[string]struct{ NetworkID, IPAddress, GlobalIPv6Address string }
	}
	if json.Unmarshal(output.Bytes(), &inspected) != nil || inspected.ID != record.ContainerID || !inspected.State.Running || inspected.State.Pid != record.ProcessID || len(inspected.Networks) > 8 {
		return nil, errProbe
	}
	var names []string
	for name := range inspected.Networks {
		names = append(names, name)
	}
	sort.Strings(names)
	var observations []generated.AccessDestinationObservation
	for _, name := range names {
		network := inspected.Networks[name]
		for _, address := range []string{network.IPAddress, network.GlobalIPv6Address} {
			if address == "" {
				continue
			}
			ip, err := netip.ParseAddr(address)
			if err != nil || ip.IsUnspecified() || ip.IsMulticast() {
				return nil, errProbe
			}
			observation := generated.AccessDestinationObservation{Schema: generated.SchemaIDAccessDestinationObservation, SchemaVersion: "1.0.0", HostID: record.HostID, IdentityDigest: record.IdentityDigest, ContextID: record.ContextID, ContextDigest: hostaction.Digest(record), ContainerID: record.ContainerID, NetworkID: network.NetworkID, Address: ip.String(), NamespaceDigest: namespace, ProcessID: int64(record.ProcessID), ProcessStart: record.ProcessStart, ObservedAt: time.Now().UTC().Format(time.RFC3339)}
			raw, _ := json.Marshal(observation)
			if generated.ValidateContractJSON(generated.SchemaIDAccessDestinationObservation, raw, generated.ContractExact) != nil {
				return nil, errProbe
			}
			observations = append(observations, observation)
		}
	}
	if len(observations) == 0 || len(observations) > 8 || !sameProbeProcess(record) {
		return nil, errProbe
	}
	after, err := os.Open(record.NamespacePath)
	if err != nil {
		return nil, errProbe
	}
	final, err := namespaceDigest(after)
	after.Close()
	if err != nil || final != namespace {
		return nil, errProbe
	}
	return observations, nil
}

package serviceruntime

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"golang.org/x/crypto/ssh"
	"net"
	"strconv"
	"strings"
	"time"
)

// CapacityObserver uses the same pinned, exact-machine SSH identity as runtime
// inspection. It is separate from Observer so older observers cannot invent a
// numeric capacity projection by returning an image receipt.
type CapacityObserver interface {
	ObserveCapacity(context.Context, Target, *credentialref.Value, Check) (CapacitySnapshot, error)
}
type CapacitySnapshot struct {
	CPUQuotaPercent, MemoryBytes, StorageBytes int64
	ObservedAt                                 string
}

const capacityCPUCommand = "/usr/bin/getconf _NPROCESSORS_ONLN"
const capacityMemoryCommand = "/usr/bin/cat /proc/meminfo"
const capacityDiskCommand = "/usr/bin/df --block-size=1 --output=avail /var/lib/docker"

func (c *Client) ObserveCapacity(ctx context.Context, t Target, value *credentialref.Value, check Check) (out CapacitySnapshot, err error) {
	if c == nil || ctx == nil || check == nil || (t.ApplicationUUID != "" && !slugRE.MatchString(t.ApplicationUUID)) || t.HostID == "" || !digestRE.MatchString(t.HostIdentityDigest) || !digestRE.MatchString(t.ExpectedMachineIDDigest) || net.ParseIP(t.Address) == nil || t.Port == 0 || t.User == "root" || !userRE.MatchString(t.User) || value == nil || len(value.Bytes()) == 0 {
		return out, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err = check(ctx); err != nil {
		return out, err
	}
	key, _, _, rest, e := ssh.ParseAuthorizedKey([]byte(t.HostKey))
	if e != nil || len(rest) != 0 {
		return out, ErrInput
	}
	signer, e := ssh.ParsePrivateKey(value.Bytes())
	if e != nil {
		return out, ErrInput
	}
	conn, e := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(t.Address, strconv.Itoa(int(t.Port))))
	if e != nil {
		return out, ErrUnavailable
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if conn.SetDeadline(deadline) != nil {
		return out, ErrUnavailable
	}
	secure, chans, requests, e := ssh.NewClientConn(conn, conn.RemoteAddr().String(), &ssh.ClientConfig{User: t.User, HostKeyCallback: ssh.FixedHostKey(key), Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}})
	if e != nil {
		return out, ErrUnavailable
	}
	client := ssh.NewClient(secure, chans, requests)
	defer client.Close()
	run := func(command string) (string, error) {
		if e := check(ctx); e != nil {
			return "", e
		}
		session, e := client.NewSession()
		if e != nil {
			return "", ErrUnavailable
		}
		defer session.Close()
		stdout := &boundedOutput{close: conn.Close, keep: true}
		stderr := &boundedOutput{close: conn.Close}
		session.Stdout = stdout
		session.Stderr = stderr
		if session.Run(command) != nil || stdout.exceeded || stderr.exceeded || ctx.Err() != nil {
			return "", ErrUnavailable
		}
		return strings.TrimSpace(stdout.buffer.String()), nil
	}
	machine := func() error {
		v, e := run(machineCommand)
		if e != nil {
			return e
		}
		if !machineRE.MatchString(v) || hostdiscovery.Digest(v) != t.ExpectedMachineIDDigest {
			return ErrIdentity
		}
		return nil
	}
	if err = machine(); err != nil {
		return out, err
	}
	raw, e := run(capacityCPUCommand)
	if e != nil {
		return out, e
	}
	cpu, e := strconv.ParseInt(raw, 10, 64)
	if e != nil || cpu < 1 || cpu > 4096 {
		return out, ErrIdentity
	}
	raw, e = run(capacityMemoryCommand)
	if e != nil {
		return out, e
	}
	var available int64
	seen := false
	for _, line := range strings.Split(raw, "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && f[0] == "MemAvailable:" {
			if seen || len(f) != 3 || f[2] != "kB" {
				return out, ErrIdentity
			}
			seen = true
			available, e = strconv.ParseInt(f[1], 10, 64)
			if e != nil || available < 1 || available > 1<<50 {
				return out, ErrIdentity
			}
			available *= 1024
		}
	}
	if !seen {
		return out, ErrIdentity
	}
	raw, e = run(capacityDiskCommand)
	if e != nil {
		return out, e
	}
	fields := strings.Fields(raw)
	if len(fields) != 2 || fields[0] != "Avail" {
		return out, ErrIdentity
	}
	disk, e := strconv.ParseInt(fields[1], 10, 64)
	if e != nil || disk < 0 {
		return out, ErrIdentity
	}
	// Account for other running Docker allocations, including applications not
	// yet imported into this controller. An unlimited/unknown allocation is not
	// spare capacity. Only this exact current managed application is excluded.
	raw, e = run(docker + "container ls --no-trunc --filter status=running --format '{{.ID}}'")
	if e != nil {
		return out, e
	}
	ids := strings.Fields(raw)
	if len(ids) > 128 {
		return out, ErrUnavailable
	}
	seenIDs := map[string]bool{}
	own := 0
	otherCPU := int64(0)
	for _, id := range ids {
		if !idRE.MatchString(id) || seenIDs[id] {
			return out, ErrIdentity
		}
		seenIDs[id] = true
		raw, e = run(docker + "container inspect --format " + quote(containerFormat) + " " + id)
		if e != nil {
			return out, e
		}
		var projection containerProjection
		if decode(ctx, []byte(raw), &projection) != nil || projection.ID != id || !projection.Running {
			return out, ErrIdentity
		}
		if t.ApplicationUUID != "" && projection.Managed == "true" && projection.Type == "application" && projection.Name == t.ApplicationUUID && projection.PullRequestID == "0" {
			own++
			if own > 1 {
				return out, ErrUnavailable
			}
			continue
		}
		quota := int64(0)
		if projection.NanoCPUs > 0 {
			quota = (projection.NanoCPUs + 9999999) / 10000000
		} else if projection.CPUQuota > 0 && projection.CPUPeriod > 0 && projection.CPUQuota <= 1000000000 && projection.CPUPeriod <= 1000000000 {
			quota = (projection.CPUQuota*100 + projection.CPUPeriod - 1) / projection.CPUPeriod
		}
		if quota <= 0 || quota > 409600 {
			return out, ErrUnavailable
		}
		otherCPU += quota
	}
	cpu = cpu*100 - otherCPU
	if err = machine(); err != nil {
		return out, err
	}
	if err = check(ctx); err != nil {
		return out, err
	}
	// Keep one CPU, ten percent of currently available memory and one GiB of disk
	// for the OS/runtime. Reservations are additionally subtracted by SQLite.
	cpu = cpu - 100
	available = available / 10 * 9
	disk -= 1 << 30
	if cpu <= 0 || available <= 0 || disk < 0 {
		return out, ErrUnavailable
	}
	return CapacitySnapshot{CPUQuotaPercent: cpu, MemoryBytes: available, StorageBytes: disk, ObservedAt: time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)}, nil
}

// Package serviceruntime observes one standalone Docker application over pinned
// SSH. It never mutates Docker, resolves credentials, or installs host software.
package serviceruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"github.com/vegastack/vegastack-labs/internal/strictjson"
	"golang.org/x/crypto/ssh"
)

type Target struct {
	HostID, HostIdentityDigest string
	ApplicationUUID            string
	Address, User, HostKey     string
	ExpectedMachineIDDigest    string
	Port                       uint16
}
type Selection struct {
	ApplicationUUID, Repository, Digest string
	CPUQuotaPercent, MemoryBytes        int64
	Environment                         []EnvironmentFingerprint
}
type Snapshot struct {
	ContainerID, ImageID, RepoDigest string
	Running                          bool
	Health, ObservedAt               string
}
type Check func(context.Context) error
type Observer interface {
	Observe(context.Context, Target, Selection, *credentialref.Value, Check) (Snapshot, error)
}
type Client struct{}

func NewClient() *Client { return &Client{} }

var (
	ErrInput       = failure.New(generated.ErrorCodeInputInvalid, "service-runtime", false)
	ErrIdentity    = failure.New(generated.ErrorCodeIntegrityFailure, "service-runtime", false)
	ErrUnavailable = failure.New(generated.ErrorCodeDependencyUnavailable, "service-runtime", false)
	digestRE       = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	idRE           = regexp.MustCompile(`^[a-f0-9]{64}$`)
	machineRE      = regexp.MustCompile(`^[a-f0-9]{32}$`)
	slugRE         = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	userRE         = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,63}$`)
	repoRE         = regexp.MustCompile(`^[a-z0-9][a-z0-9.:/_-]*$`)
)

const docker = "/usr/bin/docker --host unix:///var/run/docker.sock "
const machineCommand = "/usr/bin/cat /etc/machine-id"

// Project fields individually: Config.Env and health-check logs are secret-bearing.
const containerFormat = `{"id":{{json .Id}},"imageId":{{json .Image}},"running":{{json .State.Running}},"health":{{if .State.Health}}{{json .State.Health.Status}}{{else}}"unknown"{{end}},"managed":{{json (index .Config.Labels "coolify.managed")}},"type":{{json (index .Config.Labels "coolify.type")}},"name":{{json (index .Config.Labels "coolify.name")}},"pullRequestId":{{json (index .Config.Labels "coolify.pullRequestId")}},"nanoCpus":{{json .HostConfig.NanoCpus}},"cpuQuota":{{json .HostConfig.CpuQuota}},"cpuPeriod":{{json .HostConfig.CpuPeriod}},"memoryBytes":{{json .HostConfig.Memory}}}`
const imageFormat = `{"id":{{json .Id}},"repoDigests":{{json .RepoDigests}}}`

type containerProjection struct {
	NanoCPUs      int64  `json:"nanoCpus"`
	CPUQuota      int64  `json:"cpuQuota"`
	CPUPeriod     int64  `json:"cpuPeriod"`
	MemoryBytes   int64  `json:"memoryBytes"`
	ID            string `json:"id"`
	ImageID       string `json:"imageId"`
	Running       bool   `json:"running"`
	Health        string `json:"health"`
	Managed       string `json:"managed"`
	Type          string `json:"type"`
	Name          string `json:"name"`
	PullRequestID string `json:"pullRequestId"`
}
type imageProjection struct {
	ID          string   `json:"id"`
	RepoDigests []string `json:"repoDigests"`
}

func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
func selector(s Selection) string {
	return docker + "container ls --all --no-trunc --filter label=coolify.managed=true --filter label=coolify.type=application --filter label=coolify.name=" + s.ApplicationUUID + " --filter label=coolify.pullRequestId=0 --format '{{.ID}}'"
}
func decode(ctx context.Context, b []byte, out any) error {
	if strictjson.Scan(ctx, b, strictjson.Limits{MaxDepth: 8}) != nil {
		return ErrIdentity
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return ErrIdentity
	}
	if d.Decode(new(any)) != io.EOF {
		return ErrIdentity
	}
	return nil
}
func (c *Client) Observe(ctx context.Context, t Target, s Selection, value *credentialref.Value, check Check) (out Snapshot, err error) {
	if c == nil || ctx == nil || check == nil || t.HostID == "" || len(t.HostID) > 128 || !digestRE.MatchString(t.HostIdentityDigest) || !digestRE.MatchString(t.ExpectedMachineIDDigest) || net.ParseIP(t.Address) == nil || t.Port == 0 || t.User == "root" || !userRE.MatchString(t.User) || len(t.HostKey) > 16384 || len(s.ApplicationUUID) > 128 || !slugRE.MatchString(s.ApplicationUUID) || len(s.Repository) > 1024 || !repoRE.MatchString(s.Repository) || strings.Contains(s.Repository, "..") || !digestRE.MatchString(s.Digest) || value == nil || len(value.Bytes()) == 0 {
		return out, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err = check(ctx); err != nil {
		return out, err
	}
	key, _, _, rest, e := ssh.ParseAuthorizedKey([]byte(t.HostKey))
	if e != nil || len(rest) != 0 {
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
	if err = check(ctx); err != nil {
		return out, err
	}
	signer, e := ssh.ParsePrivateKey(value.Bytes())
	if e != nil {
		return out, ErrInput
	}
	secure, chans, requests, e := ssh.NewClientConn(conn, conn.RemoteAddr().String(), &ssh.ClientConfig{User: t.User, HostKeyCallback: ssh.FixedHostKey(key), Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}})
	if e != nil {
		return out, ErrUnavailable
	}
	client := ssh.NewClient(secure, chans, requests)
	defer client.Close()
	run := func(command string) ([]byte, error) {
		if e := check(ctx); e != nil {
			return nil, e
		}
		readCtx, cancelRead := context.WithTimeout(ctx, 5*time.Second)
		defer cancelRead()
		stopRead := context.AfterFunc(readCtx, func() { _ = conn.Close() })
		defer stopRead()
		session, e := client.NewSession()
		if e != nil {
			return nil, ErrUnavailable
		}
		defer session.Close()
		stdout := &boundedOutput{close: conn.Close, keep: true}
		stderr := &boundedOutput{close: conn.Close}
		session.Stdout = stdout
		session.Stderr = stderr
		if session.Run(command) != nil || stdout.exceeded || stderr.exceeded || readCtx.Err() != nil {
			return nil, ErrUnavailable
		}
		return stdout.buffer.Bytes(), nil
	}
	machine := func() error {
		b, e := run(machineCommand)
		if e != nil {
			return e
		}
		v := strings.TrimSpace(string(b))
		if !machineRE.MatchString(v) || hostdiscovery.Digest(v) != t.ExpectedMachineIDDigest {
			return ErrIdentity
		}
		return nil
	}
	if err = machine(); err != nil {
		return out, err
	}
	selected := func() (string, error) {
		b, e := run(selector(s))
		if e != nil {
			return "", e
		}
		ids := strings.Fields(string(b))
		if len(ids) != 1 || !idRE.MatchString(ids[0]) {
			return "", ErrUnavailable
		}
		return ids[0], nil
	}
	id, e := selected()
	if e != nil {
		return out, e
	}
	inspect := func() (containerProjection, error) {
		var p containerProjection
		b, e := run(docker + "container inspect --format " + quote(containerFormat) + " " + id)
		if e != nil {
			return p, e
		}
		if decode(ctx, b, &p) != nil || p.ID != id || !digestRE.MatchString(p.ImageID) || p.Managed != "true" || p.Type != "application" || p.Name != s.ApplicationUUID || p.PullRequestID != "0" {
			return p, ErrIdentity
		}
		if s.CPUQuotaPercent > 0 {
			if p.MemoryBytes != s.MemoryBytes || !(p.NanoCPUs == s.CPUQuotaPercent*10000000 || (p.CPUQuota > 0 && p.CPUPeriod > 0 && p.CPUQuota <= 1000000000 && p.CPUPeriod <= 1000000000 && p.CPUQuota*100 == p.CPUPeriod*s.CPUQuotaPercent)) {
				return p, ErrIdentity
			}
		}
		switch p.Health {
		case "unknown", "starting", "healthy", "unhealthy":
		default:
			return p, ErrIdentity
		}
		return p, nil
	}
	first, e := inspect()
	if e != nil {
		return out, e
	}
	if e := verifyEnvironment(s.Environment, id, run); e != nil {
		return out, e
	}
	b, e := run(docker + "image inspect --format " + quote(imageFormat) + " " + first.ImageID)
	if e != nil {
		return out, e
	}
	var image imageProjection
	if decode(ctx, b, &image) != nil || image.ID != first.ImageID || len(image.RepoDigests) > 128 {
		return out, ErrIdentity
	}
	actual := ""
	for _, d := range image.RepoDigests {
		if len(d) > 1100 {
			return out, ErrIdentity
		}
		if strings.HasPrefix(d, s.Repository+"@") {
			if !digestRE.MatchString(strings.TrimPrefix(d, s.Repository+"@")) || actual != "" && actual != d {
				return out, ErrIdentity
			}
			actual = d
		}
	}
	if actual == "" {
		return out, ErrUnavailable
	}
	second, e := inspect()
	if e != nil {
		return out, e
	}
	if first != second {
		return out, ErrUnavailable
	}
	again, e := selected()
	if e != nil {
		return out, e
	}
	if again != id {
		return out, ErrUnavailable
	}
	if err = machine(); err != nil {
		return out, err
	}
	if err = check(ctx); err != nil {
		return out, err
	}
	// A mismatch is useful actual observation, never an assertion of convergence.
	return Snapshot{ContainerID: id, ImageID: first.ImageID, RepoDigest: actual, Running: first.Running, Health: first.Health, ObservedAt: time.Now().UTC().Format(time.RFC3339)}, nil
}

type boundedOutput struct {
	buffer   bytes.Buffer
	count    int
	exceeded bool
	keep     bool
	close    func() error
}

func (w *boundedOutput) Write(p []byte) (int, error) {
	if w.count+len(p) > 16384 {
		w.exceeded = true
		_ = w.close()
		return 0, io.ErrShortBuffer
	}
	w.count += len(p)
	if w.keep {
		return w.buffer.Write(p)
	}
	return len(p), nil
}

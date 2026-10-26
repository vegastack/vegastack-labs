package workloadrecovery

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter/serviceruntime"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"golang.org/x/crypto/ssh"
)

const docker = "/usr/bin/docker --host unix:///var/run/docker.sock "

// Projection deliberately excludes environment and health logs.
const inspectFormat = `{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},"health":{{if .State.Health}}{{json .State.Health.Status}}{{else}}"unknown"{{end}},"project":{{json (index .Config.Labels "com.docker.compose.project")}},"mounts":{{json .Mounts}},"networks":{{json .NetworkSettings.Networks}},"ports":{{json .HostConfig.PortBindings}},"restart":{{json .HostConfig.RestartPolicy.Name}}}`

type mount struct {
	Type, Name, Source, Destination string
	RW                              bool
}
type inspected struct {
	ID       string                                         `json:"id"`
	Image    string                                         `json:"image"`
	Running  bool                                           `json:"running"`
	Health   string                                         `json:"health"`
	Project  string                                         `json:"project"`
	Mounts   []mount                                        `json:"mounts"`
	Networks map[string]struct{ NetworkID string }          `json:"networks"`
	Ports    map[string][]struct{ HostIP, HostPort string } `json:"ports"`
	Restart  string                                         `json:"restart"`
}
type peer struct {
	client *ssh.Client
	conn   net.Conn
	check  func(context.Context) error
	target serviceruntime.Target
}

func quote(v string) string { return "'" + strings.ReplaceAll(v, "'", "'\\''") + "'" }
func connect(ctx context.Context, t serviceruntime.Target, v *credentialref.Value, check func(context.Context) error) (*peer, error) {
	if check == nil || v == nil || net.ParseIP(t.Address) == nil || t.Port == 0 || t.User == "" || t.User == "root" || t.ExpectedMachineIDDigest == "" {
		return nil, invalid()
	}
	if e := check(ctx); e != nil {
		return nil, e
	}
	key, _, _, rest, e := ssh.ParseAuthorizedKey([]byte(t.HostKey))
	if e != nil || len(rest) != 0 {
		return nil, invalid()
	}
	signer, e := ssh.ParsePrivateKey(v.Bytes())
	if e != nil {
		return nil, invalid()
	}
	conn, e := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(t.Address, strconv.Itoa(int(t.Port))))
	if e != nil {
		return nil, unavailable()
	}
	deadline := time.Now().Add(10 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	secure, chans, reqs, e := ssh.NewClientConn(conn, conn.RemoteAddr().String(), &ssh.ClientConfig{User: t.User, HostKeyCallback: ssh.FixedHostKey(key), Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}})
	if e != nil {
		_ = conn.Close()
		return nil, unavailable()
	}
	_ = conn.SetDeadline(time.Time{})
	p := &peer{ssh.NewClient(secure, chans, reqs), conn, check, t}
	b, e := p.read(ctx, "/usr/bin/cat /etc/machine-id", 128)
	if e != nil || hostdiscovery.Digest(strings.TrimSpace(string(b))) != t.ExpectedMachineIDDigest {
		p.close()
		return nil, invalid()
	}
	return p, nil
}
func (p *peer) close() { _ = p.client.Close(); _ = p.conn.Close() }

type limitedOutput struct {
	writer    io.Writer
	remaining int64
	exceeded  bool
}

func (w *limitedOutput) Write(b []byte) (int, error) {
	if int64(len(b)) > w.remaining {
		w.exceeded = true
		return 0, io.ErrShortWrite
	}
	n, e := w.writer.Write(b)
	w.remaining -= int64(n)
	return n, e
}
func (p *peer) exchange(ctx context.Context, command string, input io.Reader, output io.Writer, max int64) error {
	if e := p.check(ctx); e != nil {
		return e
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	session, e := p.client.NewSession()
	if e != nil {
		return unavailable()
	}
	defer session.Close()
	stop := context.AfterFunc(ctx, func() { _ = session.Close() })
	defer stop()
	out := &limitedOutput{writer: output, remaining: max}
	errout := &limitedOutput{writer: io.Discard, remaining: 16384}
	session.Stdout = out
	session.Stderr = errout
	session.Stdin = input
	if session.Run(command) != nil || out.exceeded || errout.exceeded || ctx.Err() != nil {
		return unavailable()
	}
	return nil
}
func (p *peer) read(ctx context.Context, command string, max int64) ([]byte, error) {
	var b bytes.Buffer
	e := p.exchange(ctx, command, nil, &b, max)
	return b.Bytes(), e
}
func (p *peer) list(ctx context.Context, project string) ([]string, error) {
	b, e := p.read(ctx, docker+"container ls --all --no-trunc --filter "+quote("label=com.docker.compose.project="+project)+" --format '{{.ID}}'", 8192)
	if e != nil {
		return nil, e
	}
	ids := strings.Fields(string(b))
	sort.Strings(ids)
	return ids, nil
}
func (p *peer) inspect(ctx context.Context, id string) (inspected, error) {
	var out inspected
	b, e := p.read(ctx, docker+"container inspect --format "+quote(inspectFormat)+" "+quote(id), 1<<20)
	if e != nil {
		return out, e
	}
	if json.Unmarshal(b, &out) != nil {
		return out, invalid()
	}
	return out, nil
}
func (p *peer) stop(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	_, e := p.read(ctx, docker+"container stop --time 30 "+strings.Join(ids, " "), 8192)
	return e
}
func (p *peer) start(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	_, e := p.read(ctx, docker+"container start "+strings.Join(ids, " "), 8192)
	return e
}
func (p *peer) capture(ctx context.Context, id, destination string, w io.Writer, max int64) error {
	return p.exchange(ctx, docker+"container cp -a "+quote(id+":"+destination+"/.")+" -", nil, w, max)
}
func (p *peer) restore(ctx context.Context, id, destination string, r io.Reader) error {
	return p.exchange(ctx, docker+"container cp -a - "+quote(id+":"+destination), r, io.Discard, 8192)
}
func (p *peer) networkInternal(ctx context.Context, id string) bool {
	b, e := p.read(ctx, docker+"network inspect --format '{{json .Internal}}' "+quote(id), 32)
	return e == nil && strings.TrimSpace(string(b)) == "true"
}

func (p *peer) imageMatches(ctx context.Context, imageID, digest string) bool {
	if len(imageID) != 71 || !strings.HasPrefix(imageID, "sha256:") {
		return false
	}
	b, e := p.read(ctx, docker+"image inspect --format '{{json .RepoDigests}}' "+quote(imageID), 16384)
	if e != nil {
		return false
	}
	var digests []string
	if json.Unmarshal(b, &digests) != nil || len(digests) > 128 {
		return false
	}
	for _, actual := range digests {
		if strings.HasSuffix(actual, "@"+digest) {
			return true
		}
	}
	return false
}

func (p *peer) holders(ctx context.Context, source string) ([]string, error) {
	b, e := p.read(ctx, docker+"container ls --all --no-trunc --filter "+quote("volume="+source)+" --format '{{.ID}}'", 8192)
	if e != nil {
		return nil, e
	}
	return strings.Fields(string(b)), nil
}

// registryTransport reaches only the declared loopback published port through
// this already identity-checked target SSH session. TLS still verifies the
// protected registry hostname; an unrelated healthy origin cannot pass restore.
func (p *peer) registryTransport(ctx context.Context, profile generated.ServiceRecoveryProfile) (*http.Transport, error) {
	u, e := url.Parse(profile.HarborOrigin)
	if e != nil || u.Scheme != "https" || u.User != nil || u.Hostname() == "" || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, invalid()
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	n, e := strconv.Atoi(port)
	if e != nil || n < 1 || n > 65535 {
		return nil, invalid()
	}
	bound := false
	for _, component := range profile.Components {
		v, e := p.inspect(ctx, component.TargetContainerID)
		if e != nil {
			return nil, e
		}
		for _, ports := range v.Ports {
			for _, binding := range ports {
				if (binding.HostIP == "127.0.0.1" || binding.HostIP == "::1") && binding.HostPort == port {
					bound = true
				}
			}
		}
	}
	if !bound {
		return nil, blocked()
	}
	target := net.JoinHostPort("127.0.0.1", port)
	return &http.Transport{Proxy: nil, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if e := p.check(ctx); e != nil {
			return nil, e
		}
		return p.client.DialContext(ctx, "tcp", target)
	}}, nil
}

package serviceruntime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"golang.org/x/crypto/ssh"
)

func key(t *testing.T) (ssh.Signer, []byte) {
	t.Helper()
	_, p, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	s, e := ssh.NewSignerFromKey(p)
	if e != nil {
		t.Fatal(e)
	}
	b, e := ssh.MarshalPrivateKey(p, "")
	if e != nil {
		t.Fatal(e)
	}
	return s, pem.EncodeToMemory(b)
}

type peer struct {
	mu             sync.Mutex
	commands       []string
	mode           string
	containerReads int
}

func fixture(t *testing.T, mode string) (Target, Selection, *credentialref.Value, *peer) {
	t.Helper()
	server, _ := key(t)
	user, private := key(t)
	value, e := credentialref.NewValue(private)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(value.Close)
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = listener.Close() })
	config := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if !bytes.Equal(k.Marshal(), user.PublicKey().Marshal()) {
			return nil, errors.New("denied")
		}
		return nil, nil
	}}
	config.AddHostKey(server)
	p := &peer{mode: mode}
	go func() {
		conn, e := listener.Accept()
		if e != nil {
			return
		}
		defer conn.Close()
		secure, channels, requests, e := ssh.NewServerConn(conn, config)
		if e != nil {
			return
		}
		defer secure.Close()
		go ssh.DiscardRequests(requests)
		for request := range channels {
			if request.ChannelType() != "session" {
				_ = request.Reject(ssh.UnknownChannelType, "denied")
				continue
			}
			channel, reqs, e := request.Accept()
			if e != nil {
				return
			}
			go func() {
				defer channel.Close()
				for req := range reqs {
					if req.Type != "exec" {
						_ = req.Reply(false, nil)
						continue
					}
					var command struct{ Command string }
					if ssh.Unmarshal(req.Payload, &command) != nil {
						return
					}
					_ = req.Reply(true, nil)
					p.mu.Lock()
					p.commands = append(p.commands, command.Command)
					out, code := p.output(command.Command)
					p.mu.Unlock()
					_, _ = io.WriteString(channel, out)
					if code != 0 {
						_, _ = io.WriteString(channel.Stderr(), "PRIVATE-SECRET-DIAGNOSTIC")
					}
					_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{code}))
					return
				}
			}()
		}
	}()
	port, _ := strconv.Atoi(strings.Split(listener.Addr().String(), ":")[1])
	d := "sha256:" + strings.Repeat("a", 64)
	return Target{HostID: "host-one", HostIdentityDigest: d, Address: "127.0.0.1", User: "inspect", HostKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(server.PublicKey()))), ExpectedMachineIDDigest: hostdiscovery.Digest(strings.Repeat("a", 32)), Port: uint16(port)}, Selection{ApplicationUUID: "application-one", Repository: "registry.example/project/app", Digest: d}, value, p
}
func (p *peer) output(command string) (string, uint32) {
	if command == machineCommand {
		if p.mode == "machine" {
			return strings.Repeat("b", 32) + "\n", 0
		}
		return strings.Repeat("a", 32) + "\n", 0
	}
	if !strings.HasPrefix(command, docker) {
		return "", 1
	}
	if strings.Contains(command, "container ls ") {
		if p.mode == "ambiguous" {
			return strings.Repeat("1", 64) + "\n" + strings.Repeat("2", 64) + "\n", 0
		}
		if p.mode == "missing" {
			return "", 0
		}
		return strings.Repeat("1", 64) + "\n", 0
	}
	if strings.Contains(command, "container inspect ") {
		p.containerReads++
		health := "healthy"
		if p.mode == "no-health" {
			health = "unknown"
		}
		projection := containerProjection{ID: strings.Repeat("1", 64), ImageID: "sha256:" + strings.Repeat("c", 64), Running: true, Health: health, Managed: "true", Type: "application", Name: "application-one", PullRequestID: "0"}
		if p.mode == "changing" && p.containerReads > 1 {
			projection.ImageID = "sha256:" + strings.Repeat("d", 64)
		}
		if p.mode == "wrong-label" {
			projection.PullRequestID = "99"
		}
		if p.mode == "secret" {
			return `{"Config":{"Env":["PRIVATE-SECRET"]}}`, 0
		}
		b, _ := json.Marshal(projection)
		return string(b), 0
	}
	if strings.Contains(command, "image inspect ") {
		if p.mode == "denied" {
			return "", 1
		}
		if p.mode == "oversize" {
			return strings.Repeat("x", 20000), 0
		}
		d := strings.Repeat("a", 64)
		if p.mode == "mismatch" {
			d = strings.Repeat("b", 64)
		}
		b, _ := json.Marshal(imageProjection{ID: "sha256:" + strings.Repeat("c", 64), RepoDigests: []string{"registry.example/project/app@sha256:" + d}})
		return string(b), 0
	}
	return "", 1
}
func TestObservePinnedSSHRuntime(t *testing.T) {
	for _, mode := range []string{"healthy", "no-health", "mismatch"} {
		t.Run(mode, func(t *testing.T) {
			target, selection, value, p := fixture(t, mode)
			calls := 0
			out, e := NewClient().Observe(context.Background(), target, selection, value, func(context.Context) error { calls++; return nil })
			if e != nil {
				t.Fatal(e)
			}
			if out.ContainerID != strings.Repeat("1", 64) || out.ImageID != "sha256:"+strings.Repeat("c", 64) || !out.Running || out.ObservedAt == "" {
				t.Fatalf("bad snapshot: %+v", out)
			}
			if mode == "no-health" && out.Health != "unknown" {
				t.Fatal("missing healthcheck qualified")
			}
			if mode == "mismatch" && out.RepoDigest == selection.Repository+"@"+selection.Digest {
				t.Fatal("expected digest substituted for actual")
			}
			if calls < 10 {
				t.Fatalf("missing checks: %d", calls)
			}
			p.mu.Lock()
			defer p.mu.Unlock()
			if len(p.commands) != 7 {
				t.Fatalf("commands: %v", p.commands)
			}
			for _, command := range p.commands {
				if strings.Contains(command, "{{json .}}") || strings.Contains(command, ".Config.Env") || strings.Contains(command, "{{json .State.Health}}") || strings.Contains(command, "sudo") {
					t.Fatal("secret-bearing or privileged projection")
				}
				if strings.Contains(command, "container ls") && (!strings.Contains(command, "coolify.name=application-one") || !strings.Contains(command, "coolify.pullRequestId=0")) {
					t.Fatal("wrong selector")
				}
			}
			if len(value.Bytes()) == 0 {
				t.Fatal("caller credential was closed")
			}
		})
	}
}
func TestObserveDenials(t *testing.T) {
	for _, mode := range []string{"machine", "ambiguous", "missing", "changing", "wrong-label", "secret", "denied", "oversize", "host-key", "revoke"} {
		t.Run(mode, func(t *testing.T) {
			target, selection, value, p := fixture(t, mode)
			if mode == "host-key" {
				other, _ := key(t)
				target.HostKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(other.PublicKey())))
			}
			revoked := errors.New("revoked")
			calls := 0
			out, e := NewClient().Observe(context.Background(), target, selection, value, func(context.Context) error {
				calls++
				if mode == "revoke" && calls >= 5 {
					return revoked
				}
				return nil
			})
			if e == nil || out != (Snapshot{}) {
				t.Fatalf("unexpected success: %+v %v", out, e)
			}
			if strings.Contains(e.Error(), "PRIVATE-SECRET") {
				t.Fatal("remote diagnostics exposed")
			}
			if mode == "revoke" && !errors.Is(e, revoked) {
				t.Fatalf("authorization lost: %v", e)
			}
			if mode == "machine" || mode == "host-key" {
				p.mu.Lock()
				defer p.mu.Unlock()
				for _, command := range p.commands {
					if strings.HasPrefix(command, docker) {
						t.Fatal("Docker read after failed host identity")
					}
				}
			}
		})
	}
}
func TestObserveRejectsUntrustedCommandInputBeforeConnection(t *testing.T) {
	target, selection, value, _ := fixture(t, "healthy")
	selection.ApplicationUUID = "app; touch /tmp/evil"
	called := false
	_, e := NewClient().Observe(context.Background(), target, selection, value, func(context.Context) error { called = true; return nil })
	if !errors.Is(e, ErrInput) || called {
		t.Fatal("invalid selector reached connection checks")
	}
}

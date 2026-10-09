package debianaccess

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

// SocketProbe is an exact numeric tuple. Callers must bind it to approved
// identities before invoking the transport; it performs no name resolution.
type SocketProbe struct {
	Timeout       time.Duration
	SourceIP      string
	DestinationIP string
	Port          uint16
	HostKey       string
	User          string
	Kind          string // tcp, ssh-key, ssh-invalid-key, ssh-password
}
type SocketObservation struct {
	Outcome   string // allowed, denied, error
	LocalIP   string
	PinnedKey bool
}

// ProbeSocket opens one new connection for each observation. It does not run a
// remote command or create a session. PrivateKey is borrowed only for this call.
func ProbeSocket(ctx context.Context, p SocketProbe, privateKey []byte) SocketObservation {
	bad := SocketObservation{Outcome: "error"}
	src, e1 := netip.ParseAddr(p.SourceIP)
	dst, e2 := netip.ParseAddr(p.DestinationIP)
	if ctx == nil || ctx.Err() != nil || e1 != nil || e2 != nil || src.Is4() != dst.Is4() || src.IsUnspecified() || dst.IsUnspecified() || dst.IsMulticast() || p.Port == 0 {
		return bad
	}
	if p.Kind != "tcp" && p.Kind != "ssh-key" && p.Kind != "ssh-invalid-key" && p.Kind != "ssh-password" && p.Kind != "ssh-handshake" {
		return bad
	}
	var config *ssh.ClientConfig
	var pinned, attempted atomic.Bool
	if p.Kind != "tcp" {
		key, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(p.HostKey))
		if err != nil || len(rest) != 0 || p.User == "" {
			return bad
		}
		config = &ssh.ClientConfig{User: p.User, HostKeyCallback: func(host string, addr net.Addr, got ssh.PublicKey) error {
			if err := ssh.FixedHostKey(key)(host, addr, got); err != nil {
				return err
			}
			pinned.Store(true)
			return nil
		}}
		if p.Kind == "ssh-password" {
			config.Auth = []ssh.AuthMethod{ssh.PasswordCallback(func() (string, error) { attempted.Store(true); return "vsk-invalid-probe-password", nil })}
		} else {
			var signer ssh.Signer
			var err error
			if p.Kind == "ssh-invalid-key" || p.Kind == "ssh-handshake" {
				_, key, e := ed25519.GenerateKey(rand.Reader)
				if e != nil {
					return bad
				}
				signer, err = ssh.NewSignerFromKey(key)
			} else {
				signer, err = ssh.ParsePrivateKey(privateKey)
			}
			if err != nil {
				return bad
			}
			config.Auth = []ssh.AuthMethod{ssh.PublicKeysCallback(func() ([]ssh.Signer, error) { attempted.Store(true); return []ssh.Signer{signer}, nil })}
		}
	}
	timeout := p.Timeout
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	if timeout < time.Millisecond || timeout > 2*time.Second {
		return bad
	}
	bounded, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IP(src.AsSlice())}, Timeout: 2 * time.Second}
	c, err := dialer.DialContext(bounded, "tcp", net.JoinHostPort(dst.String(), strconv.Itoa(int(p.Port))))
	if err != nil {
		// A refused/timed out socket is meaningful only alongside a successful
		// same-context witness, enforced by the higher-level probe sequence.
		var ne net.Error
		if ctx.Err() == nil && (errors.Is(err, syscall.ECONNREFUSED) || (errors.As(err, &ne) && ne.Timeout())) {
			return SocketObservation{Outcome: "denied", LocalIP: src.String()}
		}
		return bad
	}
	defer c.Close()
	stop := context.AfterFunc(bounded, func() { _ = c.Close() })
	defer stop()
	deadline, _ := bounded.Deadline()
	if c.SetDeadline(deadline) != nil {
		return bad
	}
	local, ok := c.LocalAddr().(*net.TCPAddr)
	if !ok || !local.IP.Equal(net.IP(src.AsSlice())) {
		return bad
	}
	observation := SocketObservation{Outcome: "allowed", LocalIP: local.IP.String()}
	if config == nil {
		return observation
	}
	tracked := &probeConnection{Conn: c}
	secure, _, _, err := ssh.NewClientConn(tracked, c.RemoteAddr().String(), config)
	observation.PinnedKey = pinned.Load()
	if err == nil {
		_ = secure.Close()
		if p.Kind == "ssh-key" && !attempted.Load() {
			observation.Outcome = "error"
		}
		return observation
	}
	observation.Outcome = "error"
	// The pinned x/crypto version exposes authentication exhaustion only through
	// this exact diagnostic. Require it plus verified key exchange and no transport
	// failure; arbitrary handshake errors and disconnects never establish denial.
	authExhausted := strings.HasPrefix(err.Error(), "ssh: handshake failed: ssh: unable to authenticate, attempted methods [") && strings.HasSuffix(err.Error(), "], no supported methods remain")
	if pinned.Load() && authExhausted && !tracked.failed.Load() && bounded.Err() == nil {
		observation.Outcome = "denied"
		if p.Kind == "ssh-handshake" {
			observation.Outcome = "allowed"
		}
	}
	return observation
}

type probeConnection struct {
	net.Conn
	failed  atomic.Bool
	closing atomic.Bool
}

func (c *probeConnection) Read(p []byte) (int, error) {
	n, e := c.Conn.Read(p)
	if e != nil && !c.closing.Load() {
		c.failed.Store(true)
	}
	return n, e
}
func (c *probeConnection) Write(p []byte) (int, error) {
	n, e := c.Conn.Write(p)
	if e != nil && !c.closing.Load() {
		c.failed.Store(true)
	}
	return n, e
}

func (c *probeConnection) Close() error { c.closing.Store(true); return c.Conn.Close() }

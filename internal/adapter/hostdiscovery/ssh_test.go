package hostdiscovery

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	domain "github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"golang.org/x/crypto/ssh"
)

type testBorrower struct {
	key   []byte
	calls atomic.Int32
	deny  bool
	value *credentialref.Value
}

func (b *testBorrower) Check(context.Context, domain.Target) error {
	if b.deny {
		return invalid()
	}
	return nil
}
func (b *testBorrower) Borrow(context.Context, domain.Target) (*credentialref.Value, error) {
	b.calls.Add(1)
	var err error
	b.value, err = credentialref.NewValue(b.key)
	return b.value, err
}
func testKey(t *testing.T) (ssh.Signer, []byte) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatal(err)
	}
	return signer, pem.EncodeToMemory(block)
}
func fixturePeer(t *testing.T, mode string) (domain.Target, *testBorrower, *atomic.Int32) {
	t.Helper()
	host, _ := testKey(t)
	user, key := testKey(t)
	borrower := &testBorrower{key: key}
	requests := &atomic.Int32{}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if string(k.Marshal()) != string(user.PublicKey().Marshal()) {
			return nil, invalid()
		}
		return nil, nil
	}}
	config.AddHostKey(host)
	done := make(chan struct{})
	var current atomic.Pointer[net.Conn]
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		current.Store(&conn)
		defer conn.Close()
		server, channels, global, err := ssh.NewServerConn(conn, config)
		if err != nil {
			return
		}
		defer server.Close()
		go ssh.DiscardRequests(global)
		for ch := range channels {
			if ch.ChannelType() != "session" {
				t.Errorf("unexpected channel %s", ch.ChannelType())
				_ = ch.Reject(ssh.Prohibited, "")
				continue
			}
			channel, incoming, err := ch.Accept()
			if err != nil {
				return
			}
			for request := range incoming {
				if request.Type != "exec" {
					t.Errorf("unexpected SSH request %s", request.Type)
					_ = request.Reply(false, nil)
					continue
				}
				var payload struct{ Command string }
				if ssh.Unmarshal(request.Payload, &payload) != nil {
					_ = channel.Close()
					break
				}
				index := int(requests.Add(1)) - 1
				if index >= len(commands) || payload.Command != commands[index].command {
					t.Errorf("unexpected command %q", payload.Command)
					_ = channel.Close()
					break
				}
				_ = request.Reply(true, nil)
				if mode == "stall" {
					<-time.After(100 * time.Millisecond)
					_ = channel.Close()
					break
				}
				if mode == "overflow" {
					_, _ = channel.Write([]byte(strings.Repeat("x", MaxOutput+1)))
				} else {
					outputs := []string{"ID=debian\nVERSION_ID=13\n", "13.6\n", "x86_64\n", "0123456789abcdef0123456789abcdef\n", "01234567-89ab-cdef-0123-456789abcdef\n", "synthetic-serial\n", "MemTotal: 1024 kB\n", "0-3\n", `{"blockdevices":[{"name":"vda","type":"disk","size":1024}]}`, `[{"ifindex":1,"ifname":"eth0","link_type":"ether","address":"02:00:00:00:00:01"}]`}
					if index < len(outputs) {
						_, _ = channel.Write([]byte(outputs[index]))
					}
				}
				status := uint32(0)
				if mode == "partial" && index == 5 {
					_, _ = channel.Stderr().Write([]byte("SYNTHETIC-CANARY-SECRET"))
					status = 1
				}
				_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
				_ = channel.Close()
				break
			}
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		if conn := current.Load(); conn != nil {
			_ = (*conn).Close()
		}
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("fixture peer did not close")
		}
	})
	port := listener.Addr().(*net.TCPAddr).Port
	return domain.Target{Binding: generated.HostDiscoveryTarget{Schema: generated.SchemaIDHostDiscoveryTarget, SchemaVersion: "1.0.0", TargetID: "candidate-a", Revision: 1, Address: "127.0.0.1", Port: int64(port), User: "inspect", HostKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(host.PublicKey()))), ProfileID: "profile-a", CredentialReferenceID: "credential-a", MaterialVersion: "version-a", ExpectedOS: "debian", ExpectedVersion: "13", ExpectedArchitecture: "amd64"}, StateRevision: 1, GrantRevision: 1}, borrower, requests
}
func TestCollectorActualSSHBoundary(t *testing.T) {
	for _, mode := range []string{"complete", "partial", "wrong-key", "overflow", "stall"} {
		t.Run(mode, func(t *testing.T) {
			target, borrower, count := fixturePeer(t, mode)
			ctx := context.Background()
			if mode == "wrong-key" {
				other, _ := testKey(t)
				target.Binding.HostKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(other.PublicKey())))
			}
			if mode == "stall" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 20*time.Millisecond)
				defer cancel()
			}
			result, err := (&Collector{Borrower: borrower}).Collect(ctx, target)
			if mode == "complete" || mode == "partial" {
				if err != nil {
					t.Fatal(err)
				}
				if count.Load() != 10 {
					t.Fatal("incomplete command coverage")
				}
				if mode == "partial" && (len(result.Missing) != 1 || result.Missing[0] != "product-serial") {
					t.Fatal("missing fact not recorded")
				}
			} else {
				if err == nil {
					t.Fatal("unsafe collector input accepted")
				}
				if mode == "wrong-key" && (count.Load() != 0 || borrower.calls.Load() != 0) {
					t.Fatal("wrong key reached authentication or commands")
				}
			}
			if borrower.value != nil && len(borrower.value.Bytes()) != 0 {
				t.Fatal("credential was not closed")
			}
			raw, _ := json.Marshal(result)
			if strings.Contains(string(raw), "CANARY") {
				t.Fatal("remote diagnostic leaked")
			}
			if err != nil && strings.Contains(err.Error(), "CANARY") {
				t.Fatal("error leaked remote output")
			}
		})
	}
}

func TestCollectorDeniedPrerequisiteMakesNoConnection(t *testing.T) {
	target, borrower, _ := fixturePeer(t, "complete")
	borrower.deny = true
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	target.Binding.Port = int64(listener.Addr().(*net.TCPAddr).Port)
	if _, err := (&Collector{Borrower: borrower}).Collect(context.Background(), target); err == nil {
		t.Fatal("missing prerequisite allowed")
	}
	if err := listener.SetDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	conn, err := listener.Accept()
	if err == nil {
		_ = conn.Close()
		t.Fatal("denied collection dialed target")
	}
	if borrower.calls.Load() != 0 {
		t.Fatal("denied collection borrowed credential")
	}
}
func TestCollectorStalledHandshakeClosesConnection(t *testing.T) {
	target, borrower, _ := fixturePeer(t, "complete")
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	target.Binding.Port = int64(listener.Addr().(*net.TCPAddr).Port)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 1024)
		for {
			if _, err := conn.Read(buf); err != nil {
				return
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := (&Collector{Borrower: borrower}).Collect(ctx, target); err == nil {
		t.Fatal("stalled handshake passed")
	}
	select {
	case <-done:
	case <-time.After(300 * time.Millisecond):
		t.Fatal("cancelled handshake connection remains open")
	}
	if borrower.calls.Load() != 0 {
		t.Fatal("credential resolved before authenticated host key")
	}
}

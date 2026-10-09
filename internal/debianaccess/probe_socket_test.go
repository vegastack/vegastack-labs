package debianaccess

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net"
	"strconv"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestSocketProbeFreshPinnedAuthentication(t *testing.T) {
	_, hostPrivate, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(hostPrivate)
	_, userPrivate, _ := ed25519.GenerateKey(rand.Reader)
	userSigner, _ := ssh.NewSignerFromKey(userPrivate)
	raw, _ := x509.MarshalPKCS8PrivateKey(userPrivate)
	private := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var accepted atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			accepted.Add(1)
			go func() {
				defer c.Close()
				cfg := &ssh.ServerConfig{PublicKeyCallback: func(m ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
					if m.User() == "admin" && string(k.Marshal()) == string(userSigner.PublicKey().Marshal()) {
						return nil, nil
					}
					return nil, errProbeAuth{}
				}}
				cfg.AddHostKey(hostSigner)
				s, ch, r, e := ssh.NewServerConn(c, cfg)
				if e != nil {
					return
				}
				defer s.Close()
				go ssh.DiscardRequests(r)
				for channel := range ch {
					_ = channel.Reject(ssh.Prohibited, "no commands")
				}
			}()
		}
	}()
	_, portRaw, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portRaw)
	p := SocketProbe{SourceIP: "127.0.0.1", DestinationIP: "127.0.0.1", Port: uint16(port), HostKey: string(ssh.MarshalAuthorizedKey(hostSigner.PublicKey())), User: "admin", Kind: "ssh-key"}
	for _, kind := range []string{"ssh-key", "ssh-key", "ssh-invalid-key", "ssh-password", "ssh-handshake"} {
		p.Kind = kind
		got := ProbeSocket(context.Background(), p, private)
		want := "denied"
		if kind == "ssh-key" || kind == "ssh-handshake" {
			want = "allowed"
		}
		if got.Outcome != want || !got.PinnedKey || got.LocalIP != "127.0.0.1" {
			t.Fatalf("%s: %+v", kind, got)
		}
	}
	if accepted.Load() != 5 {
		t.Fatal("connection reused")
	}
	p.HostKey = string(ssh.MarshalAuthorizedKey(userSigner.PublicKey()))
	p.Kind = "ssh-key"
	if got := ProbeSocket(context.Background(), p, private); got.Outcome != "error" {
		t.Fatalf("wrong host key: %+v", got)
	}
	_ = ln.Close()
	<-done
}

type errProbeAuth struct{}

func (errProbeAuth) Error() string { return "denied" }

func TestSocketProbeInvalidSourceAndCancellationAreNotDenials(t *testing.T) {
	for _, p := range []SocketProbe{{SourceIP: "192.0.2.90", DestinationIP: "127.0.0.1", Port: 22, Kind: "tcp"}, {SourceIP: "127.0.0.1", DestinationIP: "hostname", Port: 22, Kind: "tcp"}} {
		if got := ProbeSocket(context.Background(), p, nil); got.Outcome != "error" {
			t.Fatalf("invalid source/destination became denial: %+v", got)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := ProbeSocket(ctx, SocketProbe{SourceIP: "127.0.0.1", DestinationIP: "127.0.0.1", Port: 22, Kind: "tcp"}, nil); got.Outcome != "error" {
		t.Fatal(got)
	}
}

func TestAdministratorProbeRequiresActualKeyAuthentication(t *testing.T) {
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(private)
	raw, _ := x509.MarshalPKCS8PrivateKey(private)
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, e := ln.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		config := &ssh.ServerConfig{NoClientAuth: true}
		config.AddHostKey(signer)
		s, _, _, e := ssh.NewServerConn(c, config)
		if e == nil {
			s.Close()
		}
	}()
	got := ProbeSocket(context.Background(), SocketProbe{SourceIP: "127.0.0.1", DestinationIP: "127.0.0.1", Port: uint16(ln.Addr().(*net.TCPAddr).Port), HostKey: string(ssh.MarshalAuthorizedKey(signer.PublicKey())), User: "admin", Kind: "ssh-key"}, key)
	if got.Outcome != "error" {
		t.Fatalf("unauthenticated server became key-authentication proof: %+v", got)
	}
}

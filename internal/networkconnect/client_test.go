package networkconnect

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"golang.org/x/crypto/ssh"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestConnectPinnedRoutesFreshAuthorityAndNoChannels(t *testing.T) {
	for _, scenario := range []string{"lan", "marker-mismatch", "marker-unavailable", "forced-lan", "forced-mesh", "wrong-key", "auth-denied", "before-denied", "after-denied", "after-grant-changed", "after-endpoint-changed", "after-epoch-changed"} {
		t.Run(scenario, func(t *testing.T) {
			_, private, e := ed25519.GenerateKey(rand.Reader)
			if e != nil {
				t.Fatal(e)
			}
			signer, e := ssh.NewSignerFromKey(private)
			if e != nil {
				t.Fatal(e)
			}
			block, e := ssh.MarshalPrivateKey(private, "")
			if e != nil {
				t.Fatal(e)
			}
			raw := pem.EncodeToMemory(block)
			endpoint := endpointFixture(t)
			endpoint.HostKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
			var markerCalls, lanCalls, meshCalls, channelRequests, globalRequests atomic.Int32
			marker := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				markerCalls.Add(1)
				if r.URL.Path != "/site" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
					t.Error("marker leaked request context")
				}
				_, _ = w.Write([]byte(endpoint.MarkerValue))
			}))
			defer marker.Close()
			certsum := sha256.Sum256(marker.Certificate().Raw)
			endpoint.MarkerCertificateDigest = "sha256:" + hex.EncodeToString(certsum[:])
			if scenario == "marker-mismatch" {
				endpoint.MarkerCertificateDigest = "sha256:" + strings.Repeat("a", 64)
			}
			listener, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer listener.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				conn, e := listener.Accept()
				if e != nil {
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				config := ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
					if scenario == "auth-denied" || string(k.Marshal()) != string(signer.PublicKey().Marshal()) {
						return nil, Denied()
					}
					return nil, nil
				}}
				config.AddHostKey(signer)
				connection, channels, requests, e := ssh.NewServerConn(conn, &config)
				if e != nil {
					return
				}
				defer connection.Close()
				for channels != nil || requests != nil {
					select {
					case ch, ok := <-channels:
						if !ok {
							channels = nil
						} else {
							channelRequests.Add(1)
							_ = ch.Reject(ssh.Prohibited, "diagnostic")
						}
					case req, ok := <-requests:
						if !ok {
							requests = nil
						} else {
							globalRequests.Add(1)
							if req.WantReply {
								_ = req.Reply(false, nil)
							}
						}
					}
				}
			}()
			if scenario == "wrong-key" {
				endpoint.HostKey = endpointFixture(t).HostKey
			}
			client := client{timeout: 2 * time.Second, markerTimeout: 300 * time.Millisecond, dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				host, _, _ := net.SplitHostPort(address)
				destination := listener.Addr().String()
				switch host {
				case endpoint.MarkerAddress:
					if scenario == "marker-unavailable" {
						return nil, unavailable()
					}
					destination = marker.Listener.Addr().String()
				case endpoint.LANAddress:
					lanCalls.Add(1)
				case endpoint.MeshAddress:
					meshCalls.Add(1)
				default:
					t.Error("undeclared dial", address)
					return nil, Denied()
				}
				return (&net.Dialer{}).DialContext(ctx, network, destination)
			}}
			fetches := 0
			fetch := func(context.Context) (generated.NetworkConnectDescriptor, error) {
				fetches++
				if scenario == "before-denied" || scenario == "after-denied" && fetches == 2 {
					return generated.NetworkConnectDescriptor{}, Denied()
				}
				d := generated.NetworkConnectDescriptor{Schema: generated.SchemaIDNetworkConnectDescriptor, SchemaVersion: "1.0.0", Endpoint: endpoint, EndpointDigest: "sha256:" + strings.Repeat("c", 64), StateRevision: 7, GrantRevision: 1}
				if fetches == 2 {
					switch scenario {
					case "after-grant-changed":
						d.GrantRevision++
					case "after-endpoint-changed":
						d.Endpoint.LANAddress = "10.70.0.4"
					case "after-epoch-changed":
						d.RecoveryEpoch++
					}
				}
				return d, nil
			}
			path := "auto"
			if scenario == "forced-lan" {
				path = "lan"
			}
			if scenario == "forced-mesh" {
				path = "mesh"
			}
			result, e := client.connect(context.Background(), path, raw, fetch)
			wantSuccess := scenario == "lan" || scenario == "marker-mismatch" || scenario == "marker-unavailable" || scenario == "forced-lan" || scenario == "forced-mesh"
			if (e == nil) != wantSuccess {
				t.Fatalf("success=%v expected=%v err=%v", e == nil, wantSuccess, e)
			}
			if scenario == "before-denied" {
				if lanCalls.Load()+meshCalls.Load()+markerCalls.Load() != 0 {
					t.Fatal("dial before authorization")
				}
				_ = listener.Close()
			} else if lanCalls.Load()+meshCalls.Load() != 1 {
				t.Fatal("SSH automatic retry", lanCalls.Load(), meshCalls.Load())
			}
			if wantSuccess {
				expected := "lan"
				if scenario == "marker-mismatch" || scenario == "marker-unavailable" || scenario == "forced-mesh" {
					expected = "mesh"
				}
				if result.Path != expected || result.Outcome != "authenticated-and-closed" || fetches != 2 {
					t.Fatal(result, fetches)
				}
			}
			if path != "auto" && markerCalls.Load() != 0 {
				t.Fatal("forced path probed marker")
			}
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("SSH diagnostic did not close")
			}
			if channelRequests.Load()+globalRequests.Load() != 0 {
				t.Fatal("diagnostic opened SSH session or forwarding")
			}
		})
	}
}
func TestConnectCancellationClosesHandshake(t *testing.T) {
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, e := listener.Accept()
		if e != nil {
			return
		}
		defer conn.Close()
		var b [128]byte
		for {
			if _, e := conn.Read(b[:]); e != nil {
				return
			}
		}
	}()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	block, _ := ssh.MarshalPrivateKey(key, "")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	c := client{timeout: time.Second, dial: func(ctx context.Context, n, a string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, n, listener.Addr().String())
	}}
	_, e = c.connect(ctx, "mesh", pem.EncodeToMemory(block), func(context.Context) (generated.NetworkConnectDescriptor, error) {
		return generated.NetworkConnectDescriptor{Endpoint: endpointFixture(t), GrantRevision: 1}, nil
	})
	if e == nil {
		t.Fatal("cancelled handshake succeeded")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancelled connection remained open")
	}
}
func TestPrivateKeyRequiresProtectedExplicitFile(t *testing.T) {
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "key")
	if e = os.WriteFile(path, []byte("secret-private-canary"), 0600); e != nil {
		t.Fatal(e)
	}
	if raw, e := ReadPrivateKey(context.Background(), path); e != nil || string(raw) != "secret-private-canary" {
		t.Fatal(e)
	}
	if e = os.Chmod(path, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = ReadPrivateKey(context.Background(), path); e == nil || strings.Contains(e.Error(), "secret-private-canary") {
		t.Fatal("unsafe key mode", e)
	}
	os.Chmod(path, 0600)
	link := filepath.Join(dir, "alias")
	if e = os.Symlink(path, link); e != nil {
		t.Fatal(e)
	}
	if _, e = ReadPrivateKey(context.Background(), link); e == nil {
		t.Fatal("symlink key accepted")
	}
}

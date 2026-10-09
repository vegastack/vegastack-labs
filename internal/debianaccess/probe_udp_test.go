package debianaccess

import (
	"context"
	"net"
	"sync/atomic"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestUDPRequiresConsistentAttempts(t *testing.T) {
	for _, tc := range []struct {
		name string
		echo int32
		want string
	}{
		{"allowed then denied", 1, "error"},
		{"denied then allowed", 2, "error"},
		{"all denied still runs every attempt", 0, "denied"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
			if err != nil {
				t.Fatal(err)
			}
			var attempts atomic.Int32
			done := make(chan struct{})
			go func() {
				defer close(done)
				buf := make([]byte, 128)
				for {
					n, peer, e := conn.ReadFromUDP(buf)
					if e != nil {
						return
					}
					if attempts.Add(1) == tc.echo {
						_, _ = conn.WriteToUDP(buf[:n], peer)
					}
				}
			}()
			defer func() { conn.Close(); <-done }()
			input := generated.AccessProbeInput{Attempts: 2, TimeoutMillis: 100}
			input.Source.Address = "127.0.0.1"
			tuple := generated.AccessProbeTuple{Address: "127.0.0.1", Port: int64(conn.LocalAddr().(*net.UDPAddr).Port), Protocol: "udp"}
			got := probeUDP(context.Background(), input, tuple)
			if got.Outcome != tc.want || attempts.Load() != 2 {
				t.Fatalf("outcome=%s attempts=%d; want %s and 2", got.Outcome, attempts.Load(), tc.want)
			}
		})
	}
}

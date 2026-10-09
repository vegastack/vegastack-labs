package debianaccess

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"net"
	"strconv"
	"syscall"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

// UDP qualification requires a prepared exact nonce-echo endpoint. A successful
// write alone never proves delivery; unrelated application responses do not pass.
func probeUDP(ctx context.Context, input generated.AccessProbeInput, tuple generated.AccessProbeTuple) SocketObservation {
	bad := SocketObservation{Outcome: "error"}
	var observed SocketObservation
	for attempt := int64(0); attempt < input.Attempts; attempt++ {
		bounded, cancel := context.WithTimeout(ctx, time.Duration(input.TimeoutMillis)*time.Millisecond)
		d := net.Dialer{LocalAddr: &net.UDPAddr{IP: net.ParseIP(input.Source.Address)}}
		c, err := d.DialContext(bounded, "udp", net.JoinHostPort(tuple.Address, strconv.Itoa(int(tuple.Port))))
		if err != nil {
			cancel()
			return bad
		}
		stop := context.AfterFunc(bounded, func() { _ = c.Close() })
		deadline, _ := bounded.Deadline()
		_ = c.SetDeadline(deadline)
		nonce := make([]byte, 32)
		_, err = rand.Read(nonce)
		payload := append([]byte("vsk-access-probe-v1:"), nonce...)
		if err == nil {
			_, err = c.Write(payload)
		}
		reply := make([]byte, len(payload)+1)
		var n int
		if err == nil {
			n, err = c.Read(reply)
		}
		local := c.LocalAddr().(*net.UDPAddr).IP.String()
		stop()
		_ = c.Close()
		deadlineExpired := errors.Is(bounded.Err(), context.DeadlineExceeded)
		cancel()
		if ctx.Err() != nil {
			return bad
		}
		current := SocketObservation{Outcome: "allowed", LocalIP: local}
		if err != nil {
			var ne net.Error
			if errors.Is(err, syscall.ECONNREFUSED) || deadlineExpired || (errors.As(err, &ne) && ne.Timeout()) {
				current.Outcome = "denied"
			} else {
				return bad
			}
		} else if !bytes.Equal(reply[:n], payload) {
			return bad
		}
		if attempt > 0 && current != observed {
			return bad
		}
		observed = current
	}
	if observed.Outcome == "" {
		return bad
	}
	return observed
}

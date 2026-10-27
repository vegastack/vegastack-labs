//go:build linux

package cijobrunner

import (
	"bufio"
	"context"
	"io"
	"net"
	"os"
	"time"

	"github.com/vegastack/vegastack-labs/internal/cijobguard"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

func writeHookDecision(c *net.UnixConn, d cijobguard.Decision) error {
	if hostaction.WriteFrame(c, d.Binding, cijobguard.MaxFrame) != nil || hostaction.WriteFrame(c, d, cijobguard.MaxFrame) != nil {
		return ErrProtocol
	}
	return c.CloseWrite()
}

// RunHook uses the one fixed socket; a failure can never return to the worker.
func RunHook(ctx context.Context, socket string) error {
	if socket != hookSocket || os.Getpid() == 1 || os.Geteuid() != 1001 {
		return terminateInit()
	}
	c, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: socket, Net: "unix"})
	if e != nil {
		return terminateInit()
	}
	defer c.Close()
	if c.CloseWrite() != nil {
		return terminateInit()
	}
	stop := context.AfterFunc(ctx, func() { c.Close(); _ = terminateInit() })
	defer stop()
	r := bufio.NewReaderSize(c, cijobguard.MaxFrame+2)
	raw, e := hostaction.ReadFrame(r, cijobguard.MaxFrame)
	if e != nil {
		return terminateInit()
	}
	var expected cijobguard.Binding
	if decodeFrame(ctx, raw, &expected) != nil {
		return terminateInit()
	}
	// The private PID1 validated every launch-bound field before supplying binding.
	// Preserve already buffered bytes while Close interrupts the underlying socket.
	return cijobguard.Hold(ctx, expected, time.Now().Add(time.Hour), &hookReader{Reader: r, Closer: c}, terminateInit)
}

type hookReader struct {
	io.Reader
	io.Closer
}

func RunFixedHook(ctx context.Context) error { return RunHook(ctx, hookSocket) }

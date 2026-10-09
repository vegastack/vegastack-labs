//go:build linux || darwin

package hostaction

import (
	"os"

	"golang.org/x/sys/unix"
)

// Inherited stdin/stdout pipes are ordinarily blocking descriptors. Closing
// such an os.File cannot interrupt an in-flight read/write. Give the protocol
// its own pollable handle so cancellation can interrupt the actual syscall.
func interruptiblePipe(file *os.File) (*os.File, func(), error) {
	info, err := file.Stat()
	if err != nil {
		return nil, nil, err
	}
	if info.Mode()&os.ModeNamedPipe == 0 {
		return file, func() {}, nil
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return nil, nil, err
	}
	duplicate := -1
	flags := 0
	var operationErr error
	err = raw.Control(func(fd uintptr) {
		flags, operationErr = unix.FcntlInt(fd, unix.F_GETFL, 0)
		if operationErr != nil {
			return
		}
		duplicate, operationErr = unix.Dup(int(fd))
		if operationErr != nil {
			return
		}
		unix.CloseOnExec(duplicate)
		operationErr = unix.SetNonblock(duplicate, true)
	})
	if err != nil || operationErr != nil {
		if duplicate >= 0 {
			_ = unix.Close(duplicate)
		}
		return nil, nil, blocked()
	}
	wrapped := os.NewFile(uintptr(duplicate), "host-action-protocol-pipe")
	cleanup := func() {
		_ = wrapped.Close()
		// O_NONBLOCK belongs to the shared open-file description. Restore it for
		// the caller's original handle after this finite protocol relinquishes it.
		_ = raw.Control(func(fd uintptr) { _ = unix.SetNonblock(int(fd), flags&unix.O_NONBLOCK != 0) })
	}
	return wrapped, cleanup, nil
}

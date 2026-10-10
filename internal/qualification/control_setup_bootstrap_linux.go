//go:build linux

package qualification

import (
	"context"
	"golang.org/x/sys/unix"
	"os"
	"time"
)

func awaitFixtureBootstrapProfile(ctx context.Context) error {
	f, e := os.OpenFile("/run/vsk-labs-native/bootstrap-profile-needed", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return ErrUnavailable
	}
	e = f.Sync()
	closeErr := f.Close()
	if e != nil || closeErr != nil {
		return ErrUnavailable
	}
	return awaitFixtureBootstrapProfileAt(ctx, "/run/vsk-labs-native/bootstrap-profile-ready")
}

// This marker only sequences the fixture-owned restart. It grants no API,
// execution, profile or qualification authority and never opens SQLite.
func awaitFixtureBootstrapProfileAt(ctx context.Context, path string) error {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return ErrUnavailable
		}
		e := readFixtureBootstrapMarker(path)
		if e == nil {
			return nil
		}
		if !os.IsNotExist(e) {
			return ErrUnavailable
		}
		select {
		case <-ctx.Done():
			return ErrUnavailable
		case <-ticker.C:
		}
	}
}

func readFixtureBootstrapMarker(path string) error {
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if e != nil {
		return e
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Mode&0777 != 0600 || st.Nlink != 1 || st.Size != 0 {
		return ErrUnavailable
	}
	return nil
}

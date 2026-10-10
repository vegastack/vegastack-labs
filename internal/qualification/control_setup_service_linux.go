//go:build linux

package qualification

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/linuxrole"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// This transition owns only the fixture's measured subprocess. It neither
// installs a service nor opens SQLite, and it produces no qualification receipt.
func superviseFixtureControlSuccessor(ctx context.Context, s generated.NativeSlackFixtureScope, c *fixtureControlChild, before fixtureControlHealth, profileDigest string) error {
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-c.done:
			return awaitFixtureControlSuccessor(ctx, s, before, profileDigest)
		case <-tick.C:
			e := readFixtureBootstrapMarker(slackFixtureDirectory + "/bootstrap-service-requested")
			if e == nil {
				if c.stop(syscall.SIGTERM) != nil {
					return ErrUnavailable
				}
				return awaitFixtureControlSuccessor(ctx, s, before, profileDigest)
			}
			if !os.IsNotExist(e) {
				return ErrUnavailable
			}
		}
	}
}

func awaitFixtureControlSuccessor(ctx context.Context, s generated.NativeSlackFixtureScope, before fixtureControlHealth, profileDigest string) error {
	bounded, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		if bounded.Err() != nil {
			return ErrUnavailable
		}
		if _, e := linuxrole.InspectNativeControlHandoff(bounded); e == nil {
			<-ctx.Done()
			return nil
		}
		e := readFixtureBootstrapMarker(slackFixtureDirectory + "/bootstrap-service-ready")
		if e == nil {
			after, err := fixtureReadControlHealth(bounded, s)
			digest, de := fileDigest(fixtureControlProfile, 65536)
			if err != nil || de != nil || digest != profileDigest || validateFixturePreparedService(bounded, s, before, after) != nil {
				return ErrUnavailable
			}
			<-ctx.Done()
			return nil
		}
		if !os.IsNotExist(e) {
			return ErrUnavailable
		}
		select {
		case <-bounded.Done():
			return ErrUnavailable
		case <-tick.C:
		}
	}
}

// Current API health and independent kernel reads must agree. The caller's
// protected marker sequences work only; it cannot substitute for these reads.
func validateFixturePreparedService(ctx context.Context, s generated.NativeSlackFixtureScope, before, after fixtureControlHealth) error {
	if ctx == nil || ctx.Err() != nil || s.ControlServiceUID < 1 || s.ControlServiceGID < 1 || after.PID <= 1 || after.PID > 0x7fffffff || after.PID == before.PID || before.InstanceID == "" || after.InstanceID != before.InstanceID || after.RecoveryEpoch != before.RecoveryEpoch || after.State != "ready" || !after.ReadAvailable || after.SafeMode {
		return ErrUnavailable
	}
	start, e := fixtureStartIdentity(int(after.PID))
	if e != nil {
		return ErrUnavailable
	}
	proc := "/proc/" + strconv.FormatInt(after.PID, 10)
	raw, e := os.ReadFile(proc + "/status")
	if e != nil || len(raw) > 65536 {
		return ErrUnavailable
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "Uid:" && fields[0] != "Gid:" {
			continue
		}
		if seen[fields[0]] || len(fields) != 5 {
			return ErrUnavailable
		}
		seen[fields[0]] = true
		expected := s.ControlServiceUID
		if fields[0] == "Gid:" {
			expected = s.ControlServiceGID
		}
		for _, field := range fields[1:] {
			n, e := strconv.ParseInt(field, 10, 64)
			if e != nil || n != expected {
				return ErrUnavailable
			}
		}
	}
	if !seen["Uid:"] || !seen["Gid:"] {
		return ErrUnavailable
	}
	digest, e := fileDigest(proc+"/exe", 256<<20)
	if e != nil || digest != s.ExecutableDigest {
		return ErrUnavailable
	}
	again, e := fixtureStartIdentity(int(after.PID))
	if e != nil || again != start || ctx.Err() != nil {
		return ErrUnavailable
	}
	return nil
}

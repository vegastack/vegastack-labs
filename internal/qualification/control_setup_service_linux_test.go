//go:build linux

package qualification

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"os"
	"strconv"
	"testing"
)

func TestFixturePreparedServiceChecksCurrentProcess(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires actual nonroot service-shaped process")
	}
	digest, err := fileDigest("/proc/self/exe", 256<<20)
	if err != nil {
		t.Fatal(err)
	}
	s := generated.NativeSlackFixtureScope{ControlServiceUID: int64(os.Geteuid()), ControlServiceGID: int64(os.Getegid()), ExecutableDigest: digest}
	before := fixtureControlHealth{State: "ready", ReadAvailable: true, InstanceID: "instance-test", PID: int64(os.Getpid()) + 1, RecoveryEpoch: 0}
	good := before
	good.PID = int64(os.Getpid())
	if validateFixturePreparedService(context.Background(), s, before, good) != nil {
		t.Fatal("actual unchanged-instance nonroot process rejected")
	}
	for kind, change := range map[string]func(*generated.NativeSlackFixtureScope, *fixtureControlHealth){
		"old-pid":        func(_ *generated.NativeSlackFixtureScope, h *fixtureControlHealth) { h.PID = before.PID },
		"wrong-instance": func(_ *generated.NativeSlackFixtureScope, h *fixtureControlHealth) { h.InstanceID = "other" },
		"wrong-epoch":    func(_ *generated.NativeSlackFixtureScope, h *fixtureControlHealth) { h.RecoveryEpoch++ },
		"safe-mode":      func(_ *generated.NativeSlackFixtureScope, h *fixtureControlHealth) { h.SafeMode = true },
		"wrong-uid":      func(s *generated.NativeSlackFixtureScope, _ *fixtureControlHealth) { s.ControlServiceUID++ },
		"wrong-gid":      func(s *generated.NativeSlackFixtureScope, _ *fixtureControlHealth) { s.ControlServiceGID++ },
		"wrong-executable": func(s *generated.NativeSlackFixtureScope, _ *fixtureControlHealth) {
			s.ExecutableDigest = "sha256:" + strconv.FormatInt(0, 10)
		},
	} {
		t.Run(kind, func(t *testing.T) {
			scope, h := s, good
			change(&scope, &h)
			if validateFixturePreparedService(context.Background(), scope, before, h) == nil {
				t.Fatal("foreign service preparation accepted")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if validateFixturePreparedService(ctx, s, before, good) == nil {
		t.Fatal("expired context accepted")
	}
}

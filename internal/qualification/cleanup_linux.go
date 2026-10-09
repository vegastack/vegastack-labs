//go:build linux

package qualification

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

func (d *ownedGuestLifecycle) cleanupOwned(ctx context.Context) error {
	for _, role := range []string{"subject", "custodian", "replacement", "controller"} {
		for id, g := range d.scope.guests {
			if g.Role != role {
				continue
			}
			d.mu.Lock()
			launch := d.launches[id]
			ticks, err := processStart(int(launch.QEMUPID))
			if os.IsNotExist(err) {
				d.mu.Unlock()
				continue
			}
			if err != nil || ticks != uint64(launch.QEMUStartTimeTicks) || d.checkProcess(id) != nil {
				d.mu.Unlock()
				return ErrUnavailable
			}
			_, err = ownedQMP(ctx, filepath.Join(d.scope.value.OutputRoot, id+".qmp"), int(launch.QEMUPID), qmpQuit)
			d.mu.Unlock()
			if err != nil {
				return err
			}
			timer := time.NewTicker(50 * time.Millisecond)
			stopped := false
			for !stopped {
				ticks, err = processStart(int(launch.QEMUPID))
				if os.IsNotExist(err) {
					stopped = true
					break
				}
				if err != nil || ticks != uint64(launch.QEMUStartTimeTicks) {
					timer.Stop()
					return ErrUnavailable
				}
				select {
				case <-ctx.Done():
					timer.Stop()
					return ctx.Err()
				case <-timer.C:
				}
			}
			timer.Stop()
		}
	}
	return nil
}
func writeNativeStepOutput(root string, in generated.NativeStepRequest, out generated.NativeStepResult) error {
	path := filepath.Join(root, in.ScenarioID+"-"+strconv.FormatInt(in.Ordinal, 10)+".result.json")
	raw, err := json.Marshal(out)
	if err != nil || len(raw) > 256*1024 {
		return ErrUnavailable
	}
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), path)
	_, err = f.Write(append(raw, '\n'))
	syncErr := f.Sync()
	closeErr := f.Close()
	if err != nil || syncErr != nil || closeErr != nil {
		return ErrUnavailable
	}
	directory, err := os.Open(root)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

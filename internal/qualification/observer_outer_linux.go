//go:build linux

package qualification

import (
	"bufio"
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"io"
	"path/filepath"
	"time"
)

func (d *ownedGuestLifecycle) serveObserver(ctx context.Context) error {
	controller := ""
	for id, g := range d.scope.guests {
		if g.Role == "controller" {
			controller = id
		}
	}
	if d.checkProcess(controller) != nil {
		return ErrUnavailable
	}
	conn, err := ownedSocket(ctx, filepath.Join(d.scope.value.OutputRoot, controller+".observer"), int(d.launches[controller].QEMUPID))
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	scanner := bufio.NewScanner(io.LimitReader(conn, 4*1024*1024))
	scanner.Buffer(make([]byte, 1024), 16384)
	seen := map[string]bool{}
	for scanner.Scan() {
		var b generated.NativeObservationBinding
		raw := scanner.Bytes()
		if generated.ValidateContractJSON(generated.SchemaIDNativeObservationBinding, raw, generated.ContractExact) != nil || json.Unmarshal(raw, &b) != nil {
			return ErrUnavailable
		}
		in := generated.NativeStepRequest{Schema: generated.SchemaIDNativeStepRequest, SchemaVersion: "1.0.0", ScopeDigest: b.ScopeDigest, GuestID: b.GuestID, ScenarioID: b.ScenarioID, Ordinal: b.Ordinal, ControllerInstanceID: b.ControllerInstanceID, RecoveryEpoch: b.RecoveryEpoch, PlanID: b.PlanID, PlanDigest: b.PlanDigest, RunID: b.RunID, StepID: b.StepID, LeaseID: b.LeaseID, Nonce: b.Nonce, Deadline: b.Deadline, Operation: "observe"}
		if validateStep(d.scope, in, time.Now().UTC()) != nil || seen[b.Nonce] || len(seen) >= 1024 {
			return ErrUnavailable
		}
		seen[b.Nonce] = true
		d.mu.Lock()
		err = d.checkProcess(b.GuestID)
		launch := d.launches[b.GuestID]
		boot := d.bootIDs[b.GuestID]
		if err == nil && boot != "" && time.Since(d.bootAt[b.GuestID]) <= 30*time.Second {
			var status string
			status, err = ownedQMP(ctx, filepath.Join(d.scope.value.OutputRoot, b.GuestID+".qmp"), int(launch.QEMUPID), qmpStatus)
			if status != "running" {
				err = ErrUnavailable
			}
		} else {
			err = ErrUnavailable
		}
		d.mu.Unlock()
		if err != nil {
			return err
		}
		out := generated.NativeObservation{Schema: generated.SchemaIDNativeObservation, SchemaVersion: "1.0.0", Binding: b, BootID: boot, QEMUPID: launch.QEMUPID, QEMUStartTimeTicks: launch.QEMUStartTimeTicks, ExecutableDigest: d.scope.value.ExecutableDigest, DiskDigest: launch.DiskDigest, FirmwareDigest: launch.FirmwareDigest, ObservedAt: time.Now().UTC().Truncate(time.Second).Format(time.RFC3339), ProcessState: "running", ConsoleState: "healthy", ChannelDigest: d.scope.value.ConsoleReferenceDigest}
		d.mu.Lock()
		d.attachWitness(b, &out)
		d.mu.Unlock()
		encoded, err := json.Marshal(out)
		if err != nil || generated.ValidateContractJSON(generated.SchemaIDNativeObservation, encoded, generated.ContractExact) != nil {
			return ErrUnavailable
		}
		if err = conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return err
		}
		if _, err = conn.Write(append(encoded, '\n')); err != nil {
			return err
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return ErrUnavailable
}

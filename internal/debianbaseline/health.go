package debianbaseline

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"math"
	"strconv"
	"strings"
	"time"
)

type diskObservation struct{ Total, Free uint64 }
type updateObservation struct {
	Owner                string
	SignedAt, ValidUntil time.Time
	SignatureVerified    bool
	PendingReboot        bool
	SoakSeconds          int64
	SourceDigest         string
}

func collectHealthControl(ctx context.Context, in generated.DebianBaselineInput, r NativeReader, id string) (ControlMeasurement, error) {
	c := ControlMeasurement{ControlID: id, Status: "failed", Reason: "health-policy-mismatch"}
	facts := map[string]any{}
	switch id {
	case "linux.time-sync":
		b, e := r.Read(ctx, ReadRequest{Operation: ReadTime, Selector: in.TimeOwner})
		if e != nil {
			return c, e
		}
		if in.TimeOwner == "chrony" {
			f := strings.Split(strings.TrimSpace(string(b)), ",")
			if len(f) < 13 || f[len(f)-1] != "Normal" {
				return c, nil
			}
			offset, e := strconv.ParseFloat(f[4], 64)
			if e != nil || math.IsNaN(offset) || math.IsInf(offset, 0) || math.Abs(offset) > 5 {
				return c, nil
			}
			facts["offset"] = offset
		} else {
			v := kv(b)
			if v["NTPSynchronized"] != "yes" {
				return c, nil
			}
			offset, e := strconv.ParseFloat(v["OffsetSeconds"], 64)
			if e != nil || math.IsNaN(offset) || math.IsInf(offset, 0) || math.Abs(offset) > 5 {
				return c, nil
			}
			facts["offset"] = offset
		}
	case "linux.resource-health":
		if len(in.Resources) == 0 {
			return c, errBaseline
		}
		for _, limit := range in.Resources {
			b, e := r.Read(ctx, ReadRequest{Operation: ReadUnit, Selector: limit.Unit})
			if e != nil {
				return c, e
			}
			v := kv(b)
			mem, e1 := number(v["MemoryMax"])
			tasks, e2 := number(v["TasksMax"])
			quota, e3 := parseDuration(v["CPUQuotaPerSecUSec"])
			if e1 != nil || e2 != nil || e3 != nil || mem != limit.MemoryMaxBytes || tasks != limit.TasksMax || quota != time.Duration(limit.CPUQuotaPercent)*10*time.Millisecond {
				return c, nil
			}
			b, e = r.Read(ctx, ReadRequest{Operation: ReadDisk, Selector: limit.MountPath})
			if e != nil {
				return c, e
			}
			var d diskObservation
			if decode(b, &d) != nil || d.Total == 0 || d.Free < uint64(limit.MinimumFreeBytes) || float64(d.Free)/float64(d.Total)*100 < float64(limit.MinimumFreePercent) {
				return c, nil
			}
			facts[limit.Unit] = map[string]any{"limits": v, "disk": d}
		}
	case "linux.kernel-settings":
		if len(in.KernelSettings) == 0 {
			return c, errBaseline
		}
		for _, setting := range in.KernelSettings {
			b, e := r.Read(ctx, ReadRequest{Operation: ReadKernel, Selector: setting.Name})
			if e != nil {
				return c, e
			}
			if strings.TrimSpace(string(b)) != setting.Value {
				return c, nil
			}
			facts[setting.Name] = setting.Value
		}
	case "linux.update-health":
		b, e := r.Read(ctx, ReadRequest{Operation: ReadAPT})
		if e != nil {
			return c, e
		}
		var u updateObservation
		if decode(b, &u) != nil {
			return c, errBaseline
		}
		now := time.Now().UTC()
		if !u.SignatureVerified || u.SourceDigest != in.ProfileLock.PackageSourceDigest || u.Owner != in.UpdateOwner || u.PendingReboot || u.SignedAt.After(now) || now.Sub(u.SignedAt) > 86400*time.Second || !now.Before(u.ValidUntil) || u.SoakSeconds < 604800 {
			return c, nil
		}
		facts["apt"] = u
	}
	c.Status = "passed"
	c.Reason = "current-health-observed"
	c.Facts = facts
	return c, nil
}
func parseDuration(s string) (time.Duration, error) {
	s = strings.ReplaceAll(s, "min", "m")
	return time.ParseDuration(s)
}

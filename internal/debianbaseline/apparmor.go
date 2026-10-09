package debianbaseline

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"strings"
)

func CollectAppArmor(ctx context.Context, in generated.DebianBaselineInput, r NativeReader) (ControlMeasurement, error) {
	c := ControlMeasurement{ControlID: "linux.apparmor-enforcing", Status: "failed", Reason: "profile-not-enforcing"}
	b, e := r.Read(ctx, ReadRequest{Operation: ReadAppArmor})
	if e != nil {
		return c, e
	}
	var status struct {
		Profiles map[string]string `json:"profiles"`
	}
	if decode(b, &status) != nil || len(in.AppArmorProfiles) == 0 {
		return c, errBaseline
	}
	facts := map[string]string{}
	for _, p := range in.AppArmorProfiles {
		integrity, e := r.Read(ctx, ReadRequest{Operation: ReadPackageIntegrity, Selector: p.PackageName})
		if e != nil {
			return c, e
		}
		if len(strings.TrimSpace(string(integrity))) != 0 {
			return c, nil
		}

		mode := status.Profiles[p.ProfileID]
		conventional := "/" + strings.ReplaceAll(p.ProfileID, ".", "/")
		if other, ok := status.Profiles[conventional]; ok {
			if mode != "" {
				return c, errBaseline
			}
			mode = other
		}
		if mode != "enforce" {
			return c, nil
		}
		raw, e := r.Read(ctx, ReadRequest{Operation: ReadProfile, Selector: p.ProfileID})
		if e != nil {
			return c, e
		}
		if digestBytes(raw) != p.ProfileDigest {
			return c, nil
		}
		facts[p.ProfileID] = hostaction.Digest([]string{p.ProfileDigest, "enforce"})
	}
	c.Status = "passed"
	c.Reason = "effective-enforcing-profiles-observed"
	c.Facts = facts
	return c, nil
}

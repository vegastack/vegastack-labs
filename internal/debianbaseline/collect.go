package debianbaseline

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/strictjson"
	"strconv"
	"strings"
	"time"
)

type ControlMeasurement struct {
	ControlID, Status, Reason string
	Facts                     any
}
type Result struct {
	Changed      bool
	Measurements []generated.AccessMeasurement
}

func observation(in generated.DebianBaselineInput, c ControlMeasurement, at time.Time) generated.AccessMeasurement {
	return generated.AccessMeasurement{Schema: generated.SchemaIDAccessMeasurement, SchemaVersion: "1.0.0", ControlID: c.ControlID, Kind: "baseline", PositiveProbeDigest: hostaction.BytesDigest(nil), NegativeProbeDigest: hostaction.BytesDigest(nil), Status: c.Status, Reason: c.Reason, SubjectHostID: in.HostID, SubjectIdentityDigest: in.HostIdentityDigest, ProfileLockDigest: in.ProfileLockDigest, ProducerID: "debian-baseline", ProducerVersion: "1.0.0", ObservedAt: at.UTC().Format(time.RFC3339), ConfigurationDigest: hostaction.Digest(in), Baseline: &generated.BaselineObservation{Schema: generated.SchemaIDBaselineObservation, SchemaVersion: "1.0.0", FactsDigest: hostaction.Digest(c.Facts), Verification: "configuration-observed"}}
}
func Collect(ctx context.Context, in generated.DebianBaselineInput, r NativeReader) ([]generated.AccessMeasurement, error) {
	out := []generated.AccessMeasurement{}
	for _, id := range in.ControlIDs {
		var c ControlMeasurement
		var e error
		switch id {
		case "linux.fail2ban-sshd":
			c, e = CollectFail2ban(ctx, in, r)
		case "linux.audit-bounded":
			c, e = CollectAudit(ctx, in, r)
		case "linux.apparmor-enforcing":
			c, e = CollectAppArmor(ctx, in, r)
		case "linux.aide-integrity":
			c, e = CollectAIDE(ctx, in, r)
		case "linux.update-health", "linux.time-sync", "linux.resource-health", "linux.kernel-settings":
			c, e = collectHealthControl(ctx, in, r, id)
		default:
			return nil, errBaseline
		}
		if e != nil {
			c = ControlMeasurement{ControlID: id, Status: "partial", Reason: "native-observation-unavailable", Facts: map[string]string{"control": id, "observation": "unavailable"}}
		}
		m := observation(in, c, time.Now())
		if e != nil {
			m.Baseline.Verification = "unavailable"
		}
		out = append(out, m)
	}
	return out, nil
}
func kv(b []byte) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		v := strings.Fields(line)
		if len(v) == 2 {
			m[v[0]] = v[1]
		} else if k, v, ok := strings.Cut(line, "="); ok {
			m[k] = v
		}
	}
	return m
}
func number(s string) (int64, error) { return strconv.ParseInt(strings.TrimSpace(s), 10, 64) }
func decode(b []byte, v any) error {
	if len(b) > 65536 || strictjson.Scan(context.Background(), b, strictjson.Limits{MaxDepth: 16}) != nil {
		return errBaseline
	}
	return json.Unmarshal(b, v)
}

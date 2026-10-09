package debianbaseline

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

func CollectAIDE(ctx context.Context, in generated.DebianBaselineInput, r NativeReader) (ControlMeasurement, error) {
	c := ControlMeasurement{ControlID: "linux.aide-integrity", Status: "failed", Reason: "aide-reference-or-content-drift"}
	if in.RoleID != "control" && in.RoleID != "control-plane" {
		c.Status = "partial"
		c.Reason = "control-role-only"
		return c, nil
	}
	cfg, e := r.Read(ctx, ReadRequest{Operation: ReadConfig, Selector: "aide-config"})
	if e != nil {
		return c, e
	}
	if digestBytes(cfg) != digestBytes(DesiredFiles(in)["etc/vsk-labs/baseline/aide.conf"]) {
		return c, nil
	}
	b, e := r.Read(ctx, ReadRequest{Operation: ReadConfig, Selector: "aide-reference"})
	if e != nil {
		return c, e
	}
	var ref aideReference
	if decode(b, &ref) != nil || ref.ScopeDigest != in.AIDE.ScopeDigest || ref.DatabaseDigest != in.AIDE.ReferenceDigest {
		return c, nil
	}
	db, e := r.Read(ctx, ReadRequest{Operation: ReadConfig, Selector: "aide-database"})
	if e != nil {
		return c, e
	}
	if digestBytes(db) != ref.DatabaseDigest {
		return c, nil
	}
	report, e := r.Read(ctx, ReadRequest{Operation: ReadAIDE})
	if e != nil {
		return c, e
	}
	c.Status = "passed"
	c.Reason = "current-reviewed-aide-reference-clean"
	c.Facts = map[string]string{"scope": ref.ScopeDigest, "database": ref.DatabaseDigest, "reportDigest": hostaction.Digest(string(report))}
	return c, nil
}

type aideReference struct {
	ScopeDigest          string `json:"scopeDigest"`
	DatabaseDigest       string `json:"databaseDigest"`
	ApprovedChangeDigest string `json:"approvedChangeDigest"`
}

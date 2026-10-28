package serverconfig

import (
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func heartbeatProfileFixture() generated.OperationsHeartbeatBinding {
	return generated.OperationsHeartbeatBinding{Schema: "vegastack-labs.dev/operations-heartbeat-binding", SchemaVersion: "1.0.0", Endpoint: "https://account.r2.cloudflarestorage.com", Bucket: "status-bucket", ObjectKey: "heartbeat.json", SiteDigest: "sha256:" + strings.Repeat("a", 64), TargetID: "status-target", ReferenceID: "heartbeat-ref", MaterialVersion: "v1", PolicyID: "site-alert-policy", PolicyVersion: "1.0.0"}
}
func TestSiteHeartbeatProfileIsOptionalExactAndSeparateFromBackups(t *testing.T) {
	if cfg, err := FreezeSiteHeartbeat(nil, nil); err != nil || cfg != nil {
		t.Fatal("absence enabled heartbeat")
	}
	input := heartbeatProfileFixture()
	cfg, err := FreezeSiteHeartbeat(&input, nil)
	if err != nil {
		t.Fatal(err)
	}
	first := HeartbeatCapability(*cfg)
	input.Bucket = "changed-bucket"
	if cfg.Bucket != "status-bucket" || HeartbeatCapability(input) == first {
		t.Fatal("binding aliases input or ignores exact bucket")
	}
	for _, bad := range []struct {
		name   string
		mutate func(*generated.OperationsHeartbeatBinding)
	}{{"raw endpoint", func(b *generated.OperationsHeartbeatBinding) { b.Endpoint = "http://vsk-node-04" }}, {"object", func(b *generated.OperationsHeartbeatBinding) { b.ObjectKey = "backup/data" }}, {"excluded", func(b *generated.OperationsHeartbeatBinding) { b.TargetID = "vsk-node-05" }}, {"private site", func(b *generated.OperationsHeartbeatBinding) { b.SiteDigest = "private-domain" }}} {
		t.Run(bad.name, func(t *testing.T) {
			c := heartbeatProfileFixture()
			bad.mutate(&c)
			if _, err := FreezeSiteHeartbeat(&c, nil); err == nil {
				t.Fatal("unsafe profile accepted")
			}
		})
	}
	input = heartbeatProfileFixture()
	for _, backup := range []*OffsiteBackup{{Bucket: input.Bucket}, {Bucket: "backup-bucket", ParentReferenceID: input.ReferenceID}, {Bucket: "backup-bucket", ObserverReferenceID: input.ReferenceID}} {
		if _, err := FreezeSiteHeartbeat(&input, backup); err == nil {
			t.Fatal("backup credential/bucket sharing accepted")
		}
	}
}

func TestSiteHeartbeatProtectedProfileConversionKeepsOptionalBinding(t *testing.T) {
	input := validGeneratedProfile()
	binding := heartbeatProfileFixture()
	input.OperationsHeartbeat = &binding
	profile, err := convertGeneratedProfile(input, 1001)
	if err != nil || profile.OperationsHeartbeat == nil || profile.OperationsHeartbeat.Bucket != binding.Bucket {
		t.Fatal("protected optional binding lost")
	}
	input.OperationsHeartbeat.Bucket = "changed-bucket"
	if profile.OperationsHeartbeat.Bucket != "status-bucket" {
		t.Fatal("protected runtime binding aliases decoded input")
	}
}

package serverconfig

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"strings"
	"testing"
)

func ciJobBindingFixture() generated.CiJobExecutionBinding {
	d := "sha256:" + strings.Repeat("a", 64)
	return generated.CiJobExecutionBinding{Schema: generated.SchemaIDCiJobExecutionBinding, SchemaVersion: "1.0.0", BindingID: "ci-runtime", HostID: "host-a", HostIdentityDigest: d, TargetRevision: 1, TargetDigest: d, AutomationPrincipalID: "automation-a", CallerUID: 1001, SSHReferenceID: "ssh-a", SSHMaterialVersion: "v1", RegistrationReferenceID: "registration-a", RegistrationMaterialVersion: "v1", ObserverReferenceID: "observer-a", ObserverMaterialVersion: "v1", RuntimeProfileID: "runtime-a", RuntimeDigest: d, RunnerGroupName: "isolated", MaximumSeconds: 60}
}
func TestCIJobBindingsFreezeAndRejectAmbiguity(t *testing.T) {
	b := ciJobBindingFixture()
	input := []generated.CiJobExecutionBinding{b}
	got, e := FreezeCIJobBindings(input)
	if e != nil || len(got) != 1 {
		t.Fatal(got, e)
	}
	input[0].RuntimeDigest = "changed"
	if got[0] != b {
		t.Fatal("not frozen")
	}
	for _, edit := range []func(*generated.CiJobExecutionBinding){func(b *generated.CiJobExecutionBinding) { b.ObserverReferenceID = b.SSHReferenceID }, func(b *generated.CiJobExecutionBinding) { b.CallerUID = 1 << 32 }, func(b *generated.CiJobExecutionBinding) { b.MaximumSeconds = 3601 }, func(b *generated.CiJobExecutionBinding) { b.RuntimeDigest = "unqualified" }, func(b *generated.CiJobExecutionBinding) { b.RunnerGroupName = "isolated\n" }} {
		bad := b
		edit(&bad)
		if _, e := FreezeCIJobBindings([]generated.CiJobExecutionBinding{bad}); e == nil {
			t.Fatal("invalid protected binding accepted", bad)
		}
	}
	if _, e := FreezeCIJobBindings([]generated.CiJobExecutionBinding{b, b}); e == nil {
		t.Fatal("duplicate target accepted")
	}
}

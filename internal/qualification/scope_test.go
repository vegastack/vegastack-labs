package qualification

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"testing"
	"time"
)

func scopeFixture() generated.QualificationScope {
	d := func(s string) string { return hostaction.Digest(s) }
	s := generated.QualificationScope{Schema: generated.SchemaIDQualificationScope, SchemaVersion: "1.0.0", RunID: "native-run", Purpose: "native-debian", IssuedAt: time.Now().UTC().Add(-time.Minute).Truncate(time.Second).Format(time.RFC3339), ExpiresAt: time.Now().UTC().Add(59 * time.Minute).Truncate(time.Second).Format(time.RFC3339), ControllerInstanceID: "controller-database", ControlServiceUID: 1001, ControlServiceGID: 1001, PhysicalHostID: "disposable-approved", PhysicalHostIdentityDigest: d("physical"), SourceCommit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ExecutableDigest: d("exe"), ImageDigest: d("image"), ProfileID: "debian-13-amd64", ProfileLockDigest: d("profile"), ConsoleReferenceDigest: d("console"), OutputRoot: "/runset", MaximumDurationSeconds: 3600, Resources: generated.QualificationResources{Schema: generated.SchemaIDQualificationResources, SchemaVersion: "1.0.0", CPUs: 6, MemoryBytes: 8 * GiB, StorageBytes: 80 * GiB}}
	for _, role := range []string{"controller", "subject"} {
		s.Guests = append(s.Guests, generated.QualificationGuest{Schema: generated.SchemaIDQualificationGuest, SchemaVersion: "1.0.0", GuestID: role, HostID: role + "-host", HostIdentityDigest: d(role + "-identity"), InstanceID: role + "-instance", SSHHostKeyDigest: d(role), Role: role, SnapshotID: "clean", DiskDigest: d("disk"), FirmwareDigest: d("firmware"), CPUs: 2, MemoryBytes: 3 * GiB, DiskBytes: 12 * GiB})
	}
	return s
}
func TestScopeRejectsProtectedAndExcessAggregateBeforeIO(t *testing.T) {
	if err := ValidateScope(scopeFixture()); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*generated.QualificationScope){"over-window": func(s *generated.QualificationScope) { s.MaximumDurationSeconds = 14401 }, "protected": func(s *generated.QualificationScope) { s.PhysicalHostID = "vsk-node-04" }, "guest-protected": func(s *generated.QualificationScope) { s.Guests[1].GuestID = "vsk-node-05" }, "shared-key": func(s *generated.QualificationScope) { s.Guests[1].SSHHostKeyDigest = s.Guests[0].SSHHostKeyDigest }, "memory-overhead": func(s *generated.QualificationScope) { s.Guests[0].MemoryBytes = 5 * GiB }, "storage": func(s *generated.QualificationScope) { s.Resources.StorageBytes = 24 * GiB }, "root": func(s *generated.QualificationScope) { s.OutputRoot = "/" }} {
		t.Run(name, func(t *testing.T) {
			s := scopeFixture()
			change(&s)
			if ValidateScope(s) == nil {
				t.Fatal("unsafe scope accepted")
			}
		})
	}
}

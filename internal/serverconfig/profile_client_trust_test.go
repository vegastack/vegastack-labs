package serverconfig

import "testing"

func TestServiceOwnedClientProfileTrustDecision(t *testing.T) {
	const caller, service, adminGroup = 1000, 988, 1000
	good := ProfileFileFacts{UID: service, GID: adminGroup, Mode: 0o100640}
	dir := ProfileFileFacts{UID: 0, GID: adminGroup, Mode: 0o040750}
	groups := []uint32{adminGroup}
	for _, test := range []struct {
		name   string
		file   ProfileFileFacts
		parent ProfileFileFacts
		groups []uint32
		want   bool
	}{
		{"service-owned 0640 group-readable in a root directory", good, dir, groups, true},
		{"service-owned directory is also trusted", good, ProfileFileFacts{UID: service, Mode: 0o040750}, groups, true},
		{"supplementary group membership counts", good, dir, []uint32{4, adminGroup}, true},
		{"owned by the caller is not this path", ProfileFileFacts{UID: caller, GID: adminGroup, Mode: 0o100640}, dir, groups, false},
		{"root-owned file is not a service profile", ProfileFileFacts{UID: 0, GID: adminGroup, Mode: 0o100640}, dir, groups, false},
		{"0600 cannot be read through a group", ProfileFileFacts{UID: service, GID: adminGroup, Mode: 0o100600}, dir, groups, false},
		{"0644 exposes the profile to everyone", ProfileFileFacts{UID: service, GID: adminGroup, Mode: 0o100644}, dir, groups, false},
		{"0660 lets the group rewrite it", ProfileFileFacts{UID: service, GID: adminGroup, Mode: 0o100660}, dir, groups, false},
		{"caller is not in the file group", good, dir, []uint32{4, 27}, false},
		{"no groups at all", good, dir, nil, false},
		{"group-writable directory", good, ProfileFileFacts{UID: 0, Mode: 0o040770}, groups, false},
		{"world-writable directory", good, ProfileFileFacts{UID: 0, Mode: 0o040757}, groups, false},
		{"directory owned by a third account", good, ProfileFileFacts{UID: 1234, Mode: 0o040750}, groups, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := serviceOwnedClientProfile(test.file, test.parent, caller, test.groups); got != test.want {
				t.Fatalf("trusted = %v want %v", got, test.want)
			}
		})
	}
}

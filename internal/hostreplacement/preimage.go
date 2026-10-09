package hostreplacement

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"slices"
)

// RolePreimageDigest binds the exact protected target preconditions sealed in
// the separately prepared role declaration. It asserts no observation: the
// existing role executor must still compare these preimages on the host.
func RolePreimageDigest(in generated.LinuxRoleInput) string {
	directories := append([]generated.LinuxRoleDirectory(nil), in.Directories...)
	slices.SortFunc(directories, func(a, b generated.LinuxRoleDirectory) int {
		if a.Selector < b.Selector {
			return -1
		}
		if a.Selector > b.Selector {
			return 1
		}
		return 0
	})
	accounts := append([]generated.LinuxRoleAccount(nil), in.Accounts...)
	slices.SortFunc(accounts, func(a, b generated.LinuxRoleAccount) int {
		if a.Selector < b.Selector {
			return -1
		}
		if a.Selector > b.Selector {
			return 1
		}
		return 0
	})
	return hostaction.Digest(struct {
		HostID, HostIdentityDigest, RoleID                               string
		ExpectedUnitDigest, ExpectedTmpfilesDigest, ExpectedServiceState string
		ConfigDigest, ExecutableDigest, RenderedPolicyDigest             string
		Accounts                                                         []generated.LinuxRoleAccount
		Directories                                                      []generated.LinuxRoleDirectory
	}{in.HostID, in.HostIdentityDigest, in.RoleID, in.ExpectedUnitDigest, in.ExpectedTmpfilesDigest, in.ExpectedServiceState, in.ConfigDigest, in.ExecutableDigest, in.RenderedPolicyDigest, accounts, directories})
}

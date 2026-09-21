// Package backupidentity names the only local source and repositories currently
// registered by the protected control-plane backup profile.
package backupidentity

const (
	ControlDatabaseSource   = "control-database"
	ControlDatabaseSelector = "control-database"
	StandardRepository      = "local-standard"
	CriticalRepository      = "local-critical"
)

func Registered(sourceID string, selectors []string, class string, repositoryID *string) bool {
	if sourceID != ControlDatabaseSource || len(selectors) != 1 || selectors[0] != ControlDatabaseSelector || repositoryID == nil {
		return false
	}
	switch class {
	case "standard":
		return *repositoryID == StandardRepository
	case "critical":
		return *repositoryID == CriticalRepository
	default:
		return false
	}
}

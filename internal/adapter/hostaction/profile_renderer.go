package hostaction

import (
	assets "github.com/vegastack/vegastack-labs/ansible"
	"github.com/vegastack/vegastack-labs/internal/debianaccess"
	protocol "github.com/vegastack/vegastack-labs/internal/hostaction"
)

// DebianRendererDigest binds the finite staged renderers to one protected
// profile. Changing either stage invalidates that profile's existing lock.
func DebianRendererDigest() string {
	access, err := assets.AccessRenderer.ReadFile("roles/debian_access_render/tasks/main.yml")
	if err != nil {
		return ""
	}
	baseline, err := assets.BaselineRenderer.ReadFile("roles/debian_baseline_render/tasks/main.yml")
	if err != nil {
		return ""
	}
	return protocol.Digest(map[string]string{
		"accessRole": string(access), "accessPlaybook": renderPlaybook, "accessConfig": renderConfig,
		"baselineRole": string(baseline), "baselinePlaybook": baselineRenderPlaybook, "baselineConfig": baselineRenderConfig,
		"rollbackUnits": debianaccess.RollbackUnitsDigest(),
	})
}

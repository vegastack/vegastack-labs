// Package controllerprerequisites reads a finite operator-local metadata set.
// It cannot install, qualify or change the controller or expose credential bytes.
package controllerprerequisites

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"regexp"
	"runtime"
)

var machineID = regexp.MustCompile(`^[a-f0-9]{32}$`)

func Collect(ctx context.Context, expected string) generated.ControllerPrerequisitesData {
	if !machineID.MatchString(expected) {
		if runtime.GOOS != "linux" {
			return empty("unsupported")
		}
		return empty("linux")
	}
	return collect(ctx, expected)
}
func empty(platform string) generated.ControllerPrerequisitesData {
	return generated.ControllerPrerequisitesData{Schema: generated.SchemaIDControllerPrerequisitesData, SchemaVersion: "1.0.0", Platform: platform, Facts: []generated.ControllerPrerequisiteFact{}}
}

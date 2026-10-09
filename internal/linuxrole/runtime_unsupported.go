//go:build !linux

package linuxrole

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

type unsupportedRuntime struct{}

func NewNativeRuntime(string) Runtime { return unsupportedRuntime{} }
func (unsupportedRuntime) Inspect(context.Context, generated.HostActionBundle, generated.LinuxRoleInput) error {
	return errNative
}
func (unsupportedRuntime) Apply(context.Context, generated.HostActionBundle, generated.LinuxRoleInput) (RoleResult, error) {
	return RoleResult{}, errNative
}
func (unsupportedRuntime) Collect(context.Context, generated.HostActionBundle, generated.LinuxRoleInput) (RoleResult, error) {
	return RoleResult{}, errNative
}
func (unsupportedRuntime) Handoff(context.Context, generated.HostActionBundle, generated.LinuxRoleInput) (RoleResult, error) {
	return RoleResult{}, errNative
}

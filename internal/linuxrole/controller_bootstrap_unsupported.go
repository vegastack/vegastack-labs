//go:build !linux

package linuxrole

import "context"

func VerifyControllerInstallPreconditions(context.Context, ControllerInstallInput) error {
	return errNative
}
func VerifyControllerInstallResult(context.Context, ControllerInstallInput) (string, error) {
	return "", errNative
}
func InstallControllerFoundation(context.Context, ControllerInstallInput, string) (bool, error) {
	return false, errNative
}

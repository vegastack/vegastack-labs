//go:build !linux

package linuxrole

import "context"
import "io"

func VerifyControllerInstallPreconditions(context.Context, ControllerInstallInput) error {
	return errNative
}
func VerifyControllerInstallResult(context.Context, ControllerInstallInput) (string, error) {
	return "", errNative
}
func InstallControllerFoundation(context.Context, ControllerInstallInput, string) (bool, error) {
	return false, errNative
}
func RunControllerInstall(context.Context, ControllerInstallInput, string) (bool, string, string, error) {
	return false, "failed", "", errNative
}
func WriteControllerPilotHealth(context.Context, ControllerInstallInput, io.Writer) error {
	return errNative
}
func ObserveControllerCredentialCustody(ControllerInstallInput) (string, error) { return "", errNative }
func ObserveControllerServiceCustody(ControllerInstallInput) (string, error)    { return "", errNative }

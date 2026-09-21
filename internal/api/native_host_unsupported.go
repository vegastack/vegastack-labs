//go:build !linux

package api

func localNativeHostID() (string, error) {
	return "", apiFailure("UNSUPPORTED_PLATFORM", "native-host-identity")
}

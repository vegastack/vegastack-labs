//go:build !linux

package linuxrole

import "context"

func InspectNativeControlHandoff(context.Context) (NativeControlHandoffObservation, error) {
	return NativeControlHandoffObservation{}, errNative
}

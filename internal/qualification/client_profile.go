package qualification

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"time"
)

const nativeClientProfilePath = "/etc/vsk-labs/native/client.json"

func qualificationProfileOwner(scope generated.QualificationScope, in generated.NativeStepRequest, path string, callerUID int, now time.Time) (uint32, error) {
	if callerUID != 0 || path != nativeClientProfilePath || scope.ControlServiceUID <= 0 || scope.ControlServiceUID > int64(^uint32(0)) {
		return 0, ErrUnavailable
	}
	validated, err := validateScope(scope)
	if err != nil || validateStep(validated, in, now) != nil {
		return 0, ErrUnavailable
	}
	return uint32(scope.ControlServiceUID), nil
}

func validateQualificationClientProfile(p serverconfig.Profile, uid uint32) error {
	// The root witness validates the profile before its service-UID API child. It cannot route
	// this exception through SSH or choose an alternate socket owner.
	if uid == 0 || p.SocketOwnerUID != uid || p.SocketPath == "" || p.ConstrainedSSH != nil {
		return ErrUnavailable
	}
	return nil
}

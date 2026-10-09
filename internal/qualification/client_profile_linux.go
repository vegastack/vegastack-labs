//go:build linux

package qualification

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"os"
	"time"
)

// LoadStepClientProfile is the fixed root-console fixture exception. The
// protected scope selects the nonroot profile/socket owner, never the caller.
// The API child uses this same owner and normal transport verifies the socket.
func LoadStepClientProfile(ctx context.Context, path string, in generated.NativeStepRequest) (serverconfig.Profile, error) {
	var zero serverconfig.Profile
	if os.Geteuid() != 0 || path != nativeClientProfilePath {
		return zero, ErrUnavailable
	}
	scope, err := loadGuestScope(ctx)
	if err != nil {
		return zero, err
	}
	uid, err := qualificationProfileOwner(scope, in, path, os.Geteuid(), time.Now().UTC())
	if err != nil {
		return zero, err
	}
	profile, err := serverconfig.NewLoader(uid).Load(ctx, nativeClientProfilePath)
	if err != nil {
		return zero, err
	}
	if err = validateQualificationClientProfile(profile, uid); err != nil {
		return zero, err
	}
	return profile, nil
}

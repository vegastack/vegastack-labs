package qualification

import (
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

// NativeCredentialEvidence is an internal, repository-resolved projection.
// Loaded receipts describe actual native-systemd consumers on this controller.
type NativeCredentialEvidence struct {
	Controller        generated.NativeControllerIdentity
	Binding           credentialref.LifecycleBinding
	VersionID, Status string
	Verifications     []credentialref.ConsumerVerification
}

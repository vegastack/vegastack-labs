package recovery

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/linuxrole"
	"io"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostreplacement"
)

const MaximumCandidateTransferBytes int64 = 512 << 20

// CandidateTransferDescriptor is produced from the server-owned staged
// candidate. The existing acknowledged transport must bind its complete digest;
// this is not an API accepting a caller-selected database or filesystem path.
type CandidateTransferDescriptor = generated.ControlRecoveryReceiveInput

// CandidateTransferDestination verifies fresh actual destination identity,
// installed role preimages and capacity. Production uses the privileged native
// launcher observation; a desired replacement declaration alone is insufficient.
type CandidateTransferDestination interface {
	VerifyCandidateTransferDestination(context.Context, CandidateTransferDescriptor) error
}
type CandidateTransferReceiver struct {
	DatabasePath string
	ExpectedUID  uint32
	Authority    CandidateAuthority
	Bundles      CandidateBundleStore
	Destination  CandidateTransferDestination
}
type CandidateTransferSource struct {
	Descriptor CandidateTransferDescriptor
	Candidate  io.ReadCloser
	Journal    io.ReadCloser
}

func (s *CandidateTransferSource) Close() error {
	if s == nil {
		return nil
	}
	var first error
	if s.Candidate != nil {
		first = s.Candidate.Close()
	}
	if s.Journal != nil {
		if e := s.Journal.Close(); first == nil {
			first = e
		}
	}
	return first
}
func ValidateCandidateTransferDescriptor(d CandidateTransferDescriptor) error {
	return validateCandidateTransfer(d)
}
func validateCandidateTransfer(d CandidateTransferDescriptor) error {
	if d.Schema != generated.SchemaIDControlRecoveryReceiveInput || d.SchemaVersion != "1.0.0" || d.ServiceUID <= 0 || d.ServiceUID > 4294967295 || d.ServiceGID <= 0 || d.ServiceGID > 4294967295 || linuxrole.ValidateInput(d.RoleInput) != nil || d.RoleInput.RoleID != "control" || d.RoleInput.HostID != d.Replacement.NewHostID || d.RoleInput.HostIdentityDigest != d.Replacement.NewIdentityDigest || d.RoleInput.RoleBindingDigest != d.Replacement.ProposedRoleBindingDigest || hostreplacement.RolePreimageDigest(d.RoleInput) != d.Replacement.PreservedPreimageDigest {
		return transferFailure(generated.ErrorCodePrerequisiteBlocked)
	}
	raw, err := json.Marshal(d)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDControlRecoveryReceiveInput, raw, generated.ContractExact) != nil {
		return transferFailure(generated.ErrorCodePrerequisiteBlocked)
	}
	service := false
	for _, account := range d.RoleInput.Accounts {
		if account.Selector == "control" && account.UID == d.ServiceUID && account.GID == d.ServiceGID {
			service = true
		}
	}
	if !service || d.RoleInput.ProfileID != d.Replacement.ProfileID || d.RoleInput.ProfileLockDigest != d.Replacement.ProfileLockDigest {
		return transferFailure(generated.ErrorCodePrerequisiteBlocked)
	}
	b := d.Binding
	q := d.Replacement
	if !validCandidateBinding(b) || b.ReplacementContinuity == nil || q.RestorationClass != "control-database" || hostreplacement.ValidateInput(q) != nil || hostreplacement.BindRestore(q, b) != nil || d.CandidateBytes <= 0 || d.CandidateBytes > MaximumCandidateTransferBytes || d.JournalBytes <= 0 || d.JournalBytes > 32768 || !restoreDigest.MatchString(d.CandidateBytesDigest) || !restoreDigest.MatchString(d.DatabaseDigest) || !restoreDigest.MatchString(d.JournalDigest) || !restoreDigest.MatchString(d.BundleDigest) || (d.DestinationIdentityKind != "product-serial" && d.DestinationIdentityKind != "product-uuid") {
		return transferFailure(generated.ErrorCodePrerequisiteBlocked)
	}
	journal, e := candidateTransitionBytes(b, d.DatabaseDigest)
	if e != nil || int64(len(journal)) != d.JournalBytes || digestBytes(journal) != d.JournalDigest {
		return transferFailure(generated.ErrorCodeIntegrityFailure)
	}
	return nil
}
func transferFailure(code string) error {
	return failure.New(code, "recovery-candidate-transfer", false)
}

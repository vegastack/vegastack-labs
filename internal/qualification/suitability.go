package qualification

import (
	"context"
	adapter "github.com/vegastack/vegastack-labs/internal/adapter/hostdiscovery"
	"github.com/vegastack/vegastack-labs/internal/debianaccess"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostadoption"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"regexp"
	"time"
)

// AuthorizedTarget retains the repository-resolved target and the existing
// scoped credential borrower. It cannot be populated through request JSON.
type AuthorizedTarget struct {
	target   hostdiscovery.Target
	scope    validatedNativeScope
	identity string
	borrower adapter.CredentialBorrower
}

func NewAuthorizedTarget(target hostdiscovery.Target, scope generated.QualificationScope, observedIdentityDigest string, borrower adapter.CredentialBorrower) (AuthorizedTarget, error) {
	s, err := validateScope(scope)
	if err != nil || !scopeCurrent(s, time.Now().UTC()) || borrower == nil || hostdiscovery.ValidateTarget(target.Binding) != nil || target.StateRevision < 1 || target.GrantRevision < 1 || !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(target.Digest) || observedIdentityDigest != scope.PhysicalHostIdentityDigest || debianaccess.ProtectedName(target.Binding.TargetID) || (target.Binding.AssetID != nil && debianaccess.ProtectedName(*target.Binding.AssetID)) {
		return AuthorizedTarget{}, ErrUnavailable
	}
	return AuthorizedTarget{target, s, observedIdentityDigest, borrower}, nil
}

// CollectSuitability repeats the existing bounded read-only SSH discovery with
// the registered host key and just-in-time credential. Unsupported measurements
// remain unknown: declared resources and guest records are never observations.
func CollectSuitability(ctx context.Context, target AuthorizedTarget) (generated.SuitabilityFacts, error) {
	out := generated.SuitabilityFacts{Schema: generated.SchemaIDSuitabilityFacts, SchemaVersion: "1.0.0", TargetID: target.target.Binding.TargetID, TargetRevision: target.target.Binding.Revision, TargetDigest: target.target.Digest, PhysicalHostIdentityDigest: target.identity, IdentityMatch: "unknown", HostKeyMatch: "unknown", Virtualization: "unknown", NetworkIsolation: "unknown", GuestOwnership: "unknown", WorkloadsPresent: "unknown", Architecture: "unknown", Hypervisor: "unknown", HypervisorVersion: "unknown", ObservedAt: time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)}
	if target.borrower == nil || target.scope.digest == "" {
		return out, ErrUnavailable
	}
	collected, err := (&adapter.Collector{Borrower: target.borrower}).Collect(ctx, target.target)
	if err != nil {
		return out, err
	}
	out.HostKeyMatch = "yes"
	for _, fact := range collected.Facts {
		switch fact.Name {
		case "architecture":
			out.Architecture = fact.Value
		case "product-serial":
			if hostadoption.IdentityDigest("product-serial", fact.Value) == target.identity {
				out.IdentityMatch = "yes"
			} else {
				out.IdentityMatch = "no"
			}
		}
	}
	// Discovery's MemTotal and block device sizes are not available capacity.
	// Their values intentionally cannot satisfy the capacity prerequisite.
	if out.IdentityMatch != "yes" {
		return out, ErrUnavailable
	}
	return out, nil
}

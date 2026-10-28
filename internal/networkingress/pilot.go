package networkingress

import (
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"time"
)

const PilotGateID = "ingress.controller-read-pilot"
const PilotCapability = "cloudflare.ingress.controller-read-pilot"
const PilotCollectorID = "controller-read-ingress-pilot"

// PilotPolicyDigest includes attribution and credential pins which the ordinary
// resource ownership digest deliberately does not include. No pilot pins live
// in public source; the protected profile selects its exact controller/site.
func PilotPolicyDigest(p generated.IngressControllerReadPilot) string { return Digest(p) }

func ValidatePilot(p generated.IngressControllerReadPilot) error {
	c := p.Change
	raw, _ := json.Marshal(p)
	if generated.ValidateContractJSON(generated.SchemaIDIngressControllerReadPilot, raw, generated.ContractExact) != nil {
		return Error(generated.ErrorCodeInputInvalid)
	}
	start := time.Unix(1, 0)
	binding, err := identity.BindingDigest(identity.VerifiedIdentity{Method: p.IdentityBinding.Method, Issuer: p.IdentityBinding.Issuer, Subject: p.IdentityBinding.Subject, Audiences: p.IdentityBinding.Audiences, IssuedAt: start, ExpiresAt: start.Add(time.Second)})
	if err != nil || p.IdentityBinding.Action != "bind" || p.IdentityBinding.Method != identity.CloudflareAccessMethod || binding != p.IdentityBindingDigest {
		return Error(generated.ErrorCodeInputInvalid)
	}
	if Validate(c) != nil || c.Action != "import" || c.ResourceKind != "tunnel-configuration" || len(c.Connectors) != 1 || c.Connectors[0].HostID != p.ControllerHostID || c.Connectors[0].IdentityDigest != p.ControllerIdentityDigest || !token.MatchString(p.ControllerInstanceID) || !digest.MatchString(p.ControllerMachineIDDigest) || !digest.MatchString(p.IdentityBindingDigest) || !digest.MatchString(p.IdentityProfileDigest) || p.RecoveryEpoch < 0 || len(c.AllowedGroupIDs) == 0 {
		return Error(generated.ErrorCodeInputInvalid)
	}
	return nil
}

func ValidatePilotChange(p generated.IngressControllerReadPilot, c generated.IngressChange, epoch int64) error {
	if ValidatePilot(p) != nil || Validate(c) != nil || epoch != p.RecoveryEpoch {
		return Error(generated.ErrorCodePrerequisiteBlocked)
	}
	if c.ResourceKind != "tunnel-configuration" || (c.Action != "import" && c.Action != "tunnel-config-update") {
		return Error(generated.ErrorCodeAuthorizationDenied)
	}
	// The owned tunnel retains its ordinary acknowledged import/change lifecycle.
	// Normalize only those operation fields; every target, identity, grant owner,
	// origin, policy group and credential reference remains exactly pinned.
	want := p.Change
	c.Action, c.ResourceKind, c.ResourceID = want.Action, want.ResourceKind, want.ResourceID
	c.ExpectedOwnershipRevision, c.BeforeDigest = want.ExpectedOwnershipRevision, want.BeforeDigest
	if Digest(c) != Digest(want) {
		return Error(generated.ErrorCodeAuthorizationDenied)
	}
	return nil
}

// PilotBundle contains only server-derived digests, never a user assertion or credential.
func PilotBundle(facts []generated.GateEvidenceFact, at time.Time) generated.GateEvidenceBundle {
	return generated.GateEvidenceBundle{Schema: generated.SchemaIDGateEvidenceBundle, SchemaVersion: "1.1.0", CollectorID: PilotCollectorID, ObservedAt: at.UTC().Truncate(time.Second).Format(time.RFC3339), Facts: facts, Checks: []generated.GateEvidenceCheck{{Schema: generated.SchemaIDGateEvidenceCheck, SchemaVersion: "1.1.0", CheckID: "controller-read-pilot", VerifierVersion: "1.0.0", Result: "passed", ResultDigest: Digest(facts)}}, Attachments: []generated.GateEvidenceAttachment{}}
}

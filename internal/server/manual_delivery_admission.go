package server

import (
	"context"
	"slices"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/debianaccess"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// These permissions select one exact protected configuration, not a qualified
// host or an alternative approval channel. Changing any binding requires a new
// acknowledged profile binding. Ordinary plans, credentials and leases still apply.
func manualHostingCapability(p generated.HostingLifecycleProfile) string {
	return "manual.hosting." + strings.TrimPrefix(hostaction.Digest(p), "sha256:")
}
func manualServiceCapability(s generated.ServiceProviderBinding, d generated.ServiceDeploymentProviderBinding) string {
	return "manual.service." + strings.TrimPrefix(hostaction.Digest(struct {
		Service    generated.ServiceProviderBinding
		Deployment generated.ServiceDeploymentProviderBinding
	}{s, d}), "sha256:")
}
func evaluateManualDeliveryHost(s store.HostAdmissionSnapshot, p store.GateAppliedProfile, hostID, identity string, epoch int64, capability string) error {
	blocked := func() error { return serviceFailure(generated.ErrorCodePrerequisiteBlocked) }
	if p.ProfileID != "vegastack-labs" || p.ProfileVersion != "1.0.0" || p.PolicyID != "labs-working-manual" || p.PolicyVersion != "1.0.0" || !slices.Contains(p.Capabilities, capability) ||
		(!strings.HasPrefix(capability, "manual.hosting.") && !strings.HasPrefix(capability, "manual.service.")) ||
		p.StateRevision <= 0 || p.StateRevision > s.Revision.StateRevision || p.RecoveryEpoch != epoch || s.Revision.RecoveryEpoch != epoch || s.Host.RecoveryEpoch != epoch ||
		s.AppliedProfile == nil || s.AppliedProfileDigest != hostaction.Digest(p) || hostaction.Digest(*s.AppliedProfile) != hostaction.Digest(p) ||
		s.Host.HostID != hostID || hostID == "" || debianaccess.ProtectedName(hostID) || debianaccess.ProtectedName(s.Host.TargetID) || s.Host.TargetID == "" ||
		s.Host.Status != "adopted-unadmitted" || !slices.Contains([]string{"physical", "qualified-virtual"}, s.Host.IdentityClass) || len(identity) != 71 || !strings.HasPrefix(identity, "sha256:") || s.IdentityDigest != identity {
		return blocked()
	}
	// Absent full hardening is an explicit deferral. Binding inconsistency is not.
	for _, reason := range s.Blockers {
		if reason != "host-control-missing" {
			return blocked()
		}
	}
	if slices.Contains(s.RoleBlockers, "host-binding-changed") {
		return blocked()
	}
	return nil
}
func checkManualDeliveryHost(ctx context.Context, gates *store.GateRepository, hostID, identity string, epoch int64, capability string) (bool, error) {
	if gates == nil {
		return false, serviceFailure(generated.ErrorCodePrerequisiteBlocked)
	}
	p, e := gates.GetAppliedProfileScope(ctx)
	if e != nil {
		return false, e
	}
	if p.PolicyID != "labs-working-manual" {
		return false, nil
	}
	s, e := gates.ResolveHostAdmission(ctx, hostID)
	if e != nil {
		return true, e
	}
	return true, evaluateManualDeliveryHost(s, p, hostID, identity, epoch, capability)
}
func (c *serviceDeploymentComposition) manualAdmission(ctx context.Context, d generated.ServiceDefinition, b generated.ServiceDeploymentProviderBinding, epoch int64) (bool, error) {
	s, e := c.base.binding(d)
	if e != nil {
		return false, e
	}
	selected, e := checkManualDeliveryHost(ctx, c.base.gates, d.HostID, d.HostIdentityDigest, epoch, manualServiceCapability(s, b))
	if !selected || e != nil {
		return selected, e
	}
	q := b.Configuration
	if q == nil || q.EnvironmentClass != "development" || q.Exposure != "private" || q.DataClass != "stateless" || q.Migration != "none" || q.CPUQuotaPercent <= 0 || q.MemoryBytes <= 0 || q.StorageBytes <= 0 || len(b.Artifacts) != 1 || !b.ExclusiveOwnership {
		return true, serviceFailure(generated.ErrorCodePrerequisiteBlocked)
	}
	return true, nil
}

func manualSharedCPUCapability(s generated.ServiceProviderBinding, d generated.ServiceDeploymentProviderBinding) string {
	return "manual.service.shared-cpu." + strings.TrimPrefix(manualServiceCapability(s, d), "manual.service.")
}

// Sharing requires both ordinary exact manual admission and its separate,
// acknowledged CPU choice. Absence leaves the capacity observer strict.
func (c *serviceDeploymentComposition) sharedCPUAdmission(ctx context.Context, d generated.ServiceDefinition, b generated.ServiceDeploymentProviderBinding, epoch int64) (bool, error) {
	manual, e := c.manualAdmission(ctx, d, b, epoch)
	if !manual || e != nil {
		return false, e
	}
	binding, e := c.base.binding(d)
	if e != nil {
		return false, e
	}
	capability := manualSharedCPUCapability(binding, b)
	scope, e := c.base.gates.GetAppliedProfileScope(ctx)
	if e != nil {
		return false, e
	}
	if !slices.Contains(scope.Capabilities, capability) {
		return false, nil
	}
	return checkManualDeliveryHost(ctx, c.base.gates, d.HostID, d.HostIdentityDigest, epoch, capability)
}

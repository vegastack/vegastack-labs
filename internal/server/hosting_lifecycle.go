package server

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/adapter/coolify"
	"github.com/vegastack/vegastack-labs/internal/adapter/harbor"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostinglifecycle"
	"github.com/vegastack/vegastack-labs/internal/hostingplatform"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
	"github.com/vegastack/vegastack-labs/internal/strictjson"
	"io"
	"net/http"
	"slices"
	"strconv"
	"time"
)

type hostingTarget struct {
	HostID         string `json:"hostId"`
	IdentityDigest string `json:"identityDigest"`
	Role           string `json:"role"`
}
type hostingCoolify struct {
	HostID            string                  `json:"hostId"`
	DestinationHostID string                  `json:"destinationHostId"`
	Origin            string                  `json:"origin"`
	Resources         coolify.ResourceRequest `json:"resources"`
}
type hostingHarbor struct {
	HostID      string                  `json:"hostId"`
	Origin      string                  `json:"origin"`
	Username    string                  `json:"username"`
	ReferenceID string                  `json:"referenceId"`
	Resources   harbor.LifecycleRequest `json:"resources"`
}

// Configuration is loaded exclusively from a protected profile file. TargetSet
// includes the controller, every selected destination and registry machine.
type hostingConfiguration struct {
	Targets  []hostingTarget        `json:"targets"`
	Coolify  *hostingCoolify        `json:"coolify,omitempty"`
	Harbor   *hostingHarbor         `json:"harbor,omitempty"`
	Platform *hostingplatform.Input `json:"platform,omitempty"`
}
type hostingLifecycleComposition struct {
	repo                              *store.HostingLifecycleRepository
	store                             *store.Store
	registry                          *adapter.Registry
	creds                             *store.CredentialRepository
	gates                             *store.GateRepository
	profiles                          map[string]generated.HostingLifecycleProfile
	owner                             uint32
	coolifyTransport, harborTransport http.RoundTripper
}

func hostingLifecyclePolicies(p serverconfig.Profile) ([]hostinglifecycle.Profile, error) {
	out := []hostinglifecycle.Profile{}
	seen := map[string]bool{}
	for _, b := range p.HostingLifecycleProfiles {
		raw, _ := json.Marshal(b)
		if seen[b.TargetID] || generated.ValidateContractJSON(generated.SchemaIDHostingLifecycleProfile, raw, generated.ContractExact) != nil {
			return nil, serviceFailure(generated.ErrorCodeInputInvalid)
		}
		seen[b.TargetID] = true
		out = append(out, hostinglifecycle.Profile{Binding: b})
	}
	return out, nil
}
func newHostingLifecycleComposition(p serverconfig.Profile, s *store.Store, registry *adapter.Registry) (*hostingLifecycleComposition, error) {
	if s == nil || registry == nil {
		return nil, serviceFailure(generated.ErrorCodeInputInvalid)
	}
	ps, e := hostingLifecyclePolicies(p)
	if e != nil {
		return nil, e
	}
	c := &hostingLifecycleComposition{repo: store.NewHostingLifecycleRepository(s), store: s, registry: registry, creds: store.NewCredentialRepository(s), gates: store.NewGateRepository(s), profiles: map[string]generated.HostingLifecycleProfile{}, owner: p.SocketOwnerUID}
	for _, q := range ps {
		c.profiles[q.Binding.TargetID] = q.Binding
	}
	return c, nil
}
func (c *hostingLifecycleComposition) configuration(ctx context.Context, q generated.HostingLifecycleRequest) (hostingConfiguration, generated.HostingLifecycleProfile, error) {
	var out hostingConfiguration
	p, ok := c.profiles[q.TargetID]
	if !ok || p.BindingID != q.BindingID || p.ConfigurationDigest != q.ConfigurationDigest {
		return out, p, serviceFailure(generated.ErrorCodePlanStale)
	}
	raw, e := readLocalSetupProtected(ctx, p.ConfigurationPath, c.owner, 1<<20)
	if e != nil || hostaction.BytesDigest(raw) != p.ConfigurationDigest {
		return out, p, serviceFailure(generated.ErrorCodePlanStale)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if e = dec.Decode(&out); e != nil || dec.Decode(new(any)) != io.EOF || strictjson.Scan(ctx, raw, strictjson.Limits{MaxDepth: 24}) != nil || len(out.Targets) == 0 || len(out.Targets) > 16 || (out.Coolify == nil && out.Harbor == nil && out.Platform == nil) {
		return out, p, serviceFailure(generated.ErrorCodeInputInvalid)
	}
	seen := map[string]bool{}
	for _, t := range out.Targets {
		if seen[t.HostID] || len(t.IdentityDigest) != 71 || (t.Role != "control" && t.Role != "application") {
			return out, p, serviceFailure(generated.ErrorCodeInputInvalid)
		}
		seen[t.HostID] = true
	}
	if out.Coolify != nil && (!seen[out.Coolify.HostID] || !seen[out.Coolify.DestinationHostID]) {
		return out, p, serviceFailure(generated.ErrorCodeInputInvalid)
	}
	if out.Harbor != nil && !seen[out.Harbor.HostID] {
		return out, p, serviceFailure(generated.ErrorCodeInputInvalid)
	}
	return out, p, nil
}
func (c *hostingLifecycleComposition) checkTargets(ctx context.Context, q generated.HostingLifecycleRequest, conf hostingConfiguration) error {
	if e := c.repo.Authorize(ctx, q); e != nil {
		return e
	}
	for _, t := range conf.Targets {
		if e := c.repo.CheckTarget(ctx, q, t.HostID, t.IdentityDigest); e != nil {
			return e
		}
		a, e := (hostReplacementComposition{gates: c.gates, clock: time.Now}).roleAdmission(ctx, t.HostID)
		if e != nil {
			return e
		}
		if a.IdentityDigest != t.IdentityDigest || a.Profile.RoleID != t.Role || a.Revision.RecoveryEpoch != q.RecoveryEpoch {
			return serviceFailure(generated.ErrorCodePrerequisiteBlocked)
		}
	}
	return nil
}
func (c *hostingLifecycleComposition) credential(ctx context.Context, q generated.HostingLifecycleRequest, conf hostingConfiguration, id, consumer, purpose, cap string) (credentialref.StepBinding, serviceCredentialIdentity, error) {
	var z credentialref.StepBinding
	var identity serviceCredentialIdentity
	if e := c.checkTargets(ctx, q, conf); e != nil {
		return z, identity, e
	}
	health, e := c.store.Health(ctx)
	if e != nil {
		return z, identity, e
	}
	scope, e := c.gates.GetAppliedProfileScope(ctx)
	if e != nil || scope.RecoveryEpoch != q.RecoveryEpoch || !slices.Contains(scope.Capabilities, cap) {
		return z, identity, serviceFailure(generated.ErrorCodePrerequisiteBlocked)
	}
	r, e := c.creds.GetReference(ctx, id)
	if e != nil || r.Status != "active" || r.ConsumerID != consumer || r.PurposeID != purpose || r.TargetID != q.TargetID || r.RecoveryEpoch != q.RecoveryEpoch || r.StateRevision > health.Revision.StateRevision || r.ActivatedAt == nil || !slices.Contains(r.VerifiedConsumerIDs, consumer) {
		return z, identity, serviceFailure(generated.ErrorCodePrerequisiteBlocked)
	}
	actual, e := c.registry.ResolveCredentialCapability(r.ResolverID, consumer, scope.ProfileID)
	if e != nil || actual != cap {
		return z, identity, serviceFailure(generated.ErrorCodePrerequisiteBlocked)
	}
	z = credentialref.StepBinding{OperationID: hostinglifecycle.OperationID, AdapterID: consumer, ConsumerID: consumer, PurposeID: purpose, TargetID: q.TargetID, ReferenceID: id, ResolverID: r.ResolverID, MaterialVersion: r.MaterialVersion, StateRevision: health.Revision.StateRevision, RecoveryEpoch: q.RecoveryEpoch}
	identity = serviceCredentialIdentity{ReferenceID: id, ConsumerID: consumer, PurposeID: purpose, TargetID: q.TargetID, ResolverID: r.ResolverID, MaterialVersion: r.MaterialVersion, Fingerprint: r.Fingerprint, ProfileDigest: serviceProfileDigest(scope), ReferenceStateRevision: r.StateRevision, RecoveryEpoch: q.RecoveryEpoch}
	return z, identity, nil
}
func (c *hostingLifecycleComposition) borrow(ctx context.Context, q generated.HostingLifecycleRequest, conf hostingConfiguration, id, consumer, purpose, cap string) (*credentialref.Value, func() error, error) {
	b, initial, e := c.credential(ctx, q, conf, id, consumer, purpose, cap)
	if e != nil {
		return nil, nil, e
	}
	scope, e := c.gates.GetAppliedProfileScope(ctx)
	if e != nil {
		return nil, nil, e
	}
	resolver, e := c.registry.ResolveCredentialResolver(b.ResolverID, consumer, scope.ProfileID)
	if e != nil {
		return nil, nil, e
	}
	v, e := resolver.Resolve(ctx, b)
	if e != nil {
		return nil, nil, e
	}
	check := func() error {
		_, now, e := c.credential(ctx, q, conf, id, consumer, purpose, cap)
		if e != nil {
			return e
		}
		if now != initial {
			return serviceFailure(generated.ErrorCodePlanStale)
		}
		return nil
	}
	if v == nil || len(v.Bytes()) == 0 || check() != nil {
		if v != nil {
			v.Close()
		}
		return nil, nil, serviceFailure(generated.ErrorCodePlanStale)
	}
	return v, check, nil
}
func (c *hostingLifecycleComposition) applyOwnership(ctx context.Context, q generated.HostingLifecycleRequest, conf *hostingConfiguration) error {
	owned, e := c.repo.OwnedResources(ctx, q)
	if e != nil {
		return e
	}
	for _, r := range owned {
		if conf.Coolify != nil {
			b := &conf.Coolify.Resources
			switch r.Kind {
			case "coolify-project":
				if b.ProjectUUID != "" && b.ProjectUUID != r.ExternalID {
					return serviceFailure(generated.ErrorCodeIntegrityFailure)
				}
				b.ProjectUUID = r.ExternalID
			case "coolify-application":
				b.ApplicationUUID = r.ExternalID
			case "coolify-service":
				b.ServiceUUID = r.ExternalID
			}
		}
		if conf.Harbor != nil {
			b := &conf.Harbor.Resources
			for i := range b.Projects {
				if b.Projects[i].Name == r.ParentID {
					n, e := strconv.ParseInt(r.ExternalID, 10, 64)
					if e != nil {
						return e
					}
					if r.Kind == "harbor-project" {
						b.Projects[i].ID = n
					}
					if r.Kind == "harbor-retention" {
						b.Projects[i].RetentionID = n
					}
				}
			}
			for i := range b.Robots {
				if b.Robots[i].ReferenceID == r.ParentID && r.Kind == "harbor-robot" {
					n, e := strconv.ParseInt(r.ExternalID, 10, 64)
					if e != nil {
						return e
					}
					b.Robots[i].ID = n
				}
			}
		}
	}
	return nil
}
func (c *hostingLifecycleComposition) observe(ctx context.Context, q generated.HostingLifecycleRequest, conf hostingConfiguration, p generated.HostingLifecycleProfile, apply bool) (hostinglifecycle.Outcome, error) {
	out := hostinglifecycle.Outcome{Status: "partial", OwnedResources: []generated.HostingOwnedResource{}}
	if e := c.checkTargets(ctx, q, conf); e != nil {
		return out, e
	}
	var snapshot []any
	if conf.Coolify != nil {
		b := conf.Coolify
		client, e := coolify.NewClient(b.Origin, c.coolifyTransport)
		if e != nil {
			return out, e
		}
		v, check, e := c.borrow(ctx, q, conf, p.MutationReferenceID, "hosting.coolify.deploy", "hosting-deploy", "credential.hosting.deploy")
		if e != nil {
			return out, e
		}
		defer v.Close()
		b.Resources.Check = check
		var s coolify.ResourceSnapshot
		if apply {
			s, e = client.ApplyResources(ctx, b.Resources, v)
		} else {
			s, e = client.ObserveResources(ctx, b.Resources, v)
		}
		for _, r := range []struct{ k, id, parent string }{{"coolify-project", s.ProjectUUID, strconv.FormatInt(s.TeamID, 10)}, {"coolify-environment", strconv.FormatInt(s.EnvironmentID, 10), s.ProjectUUID}, {"coolify-application", s.ApplicationUUID, s.ProjectUUID}, {"coolify-service", s.ServiceUUID, s.ProjectUUID}} {
			if r.id != "" && r.id != "0" {
				out.OwnedResources = append(out.OwnedResources, generated.HostingOwnedResource{Schema: generated.SchemaIDHostingOwnedResource, SchemaVersion: "1.0.0", Kind: r.k, ExternalID: r.id, ParentID: r.parent})
			}
		}
		if e != nil {
			return out, e
		}
		snapshot = append(snapshot, s)
	}
	if conf.Harbor != nil {
		b := conf.Harbor
		client, e := harbor.NewClient(b.Origin, c.harborTransport)
		if e != nil {
			return out, e
		}
		v, check, e := c.borrow(ctx, q, conf, b.ReferenceID, "registry.harbor.manage", "registry-manage", "credential.registry.manage")
		if e != nil {
			return out, e
		}
		defer v.Close()
		robotValues := map[string]*credentialref.Value{}
		robotChecks := []func() error{}
		for _, r := range b.Resources.Robots {
			consumer, purpose, cap := "registry.harbor.deploy", "registry-pull", "credential.registry.pull"
			if r.Push {
				consumer, purpose, cap = "registry.harbor.ci", "registry-push", "credential.registry.push"
			}
			ref, e := c.creds.GetReference(ctx, r.ReferenceID)
			if e != nil || ref.MaterialVersion != r.MaterialVersion {
				return out, serviceFailure(generated.ErrorCodePlanStale)
			}
			value, recheck, e := c.borrow(ctx, q, conf, r.ReferenceID, consumer, purpose, cap)
			if e != nil {
				return out, e
			}
			defer value.Close()
			robotValues[r.ReferenceID] = value
			robotChecks = append(robotChecks, recheck)
		}
		b.Resources.Check = func() error {
			if e := check(); e != nil {
				return e
			}
			for _, current := range robotChecks {
				if e := current(); e != nil {
					return e
				}
			}
			return nil
		}

		var s harbor.LifecycleSnapshot
		if apply {
			source := func(ctx context.Context, r harbor.RobotBinding) (*credentialref.Value, error) {
				if e := b.Resources.Check(); e != nil {
					return nil, e
				}
				v := robotValues[r.ReferenceID]
				if v == nil {
					return nil, serviceFailure(generated.ErrorCodePrerequisiteBlocked)
				}
				return credentialref.NewValue(v.Bytes())
			}

			s, e = client.ApplyLifecycleWithSecrets(ctx, b.Resources, b.Username, v, source)
		} else {
			s, e = client.ObserveLifecycle(ctx, b.Resources, b.Username, v)
		}
		for _, p := range s.Projects {
			out.OwnedResources = append(out.OwnedResources, generated.HostingOwnedResource{Schema: generated.SchemaIDHostingOwnedResource, SchemaVersion: "1.0.0", Kind: "harbor-project", ExternalID: strconv.FormatInt(p.ID, 10), ParentID: p.Name}, generated.HostingOwnedResource{Schema: generated.SchemaIDHostingOwnedResource, SchemaVersion: "1.0.0", Kind: "harbor-retention", ExternalID: strconv.FormatInt(p.RetentionID, 10), ParentID: p.Name})
		}
		for _, r := range s.Robots {
			out.OwnedResources = append(out.OwnedResources, generated.HostingOwnedResource{Schema: generated.SchemaIDHostingOwnedResource, SchemaVersion: "1.0.0", Kind: "harbor-robot", ExternalID: strconv.FormatInt(r.ID, 10), ParentID: r.ReferenceID})
		}
		if e != nil {
			return out, e
		}
		snapshot = append(snapshot, s)
	}
	if e := c.checkTargets(ctx, q, conf); e != nil {
		return out, e
	}
	out.Status = "succeeded"
	out.ResultDigest = hostinglifecycle.Digest(snapshot)
	return out, nil
}
func (c *hostingLifecycleComposition) Prepare(ctx context.Context, d generated.HostingLifecycleDraftRequest) (generated.HostingLifecycleRequest, error) {
	q, e := c.repo.Prepare(ctx, d)
	if e != nil {
		return q, e
	}
	conf, p, e := c.configuration(ctx, q)
	if e != nil {
		return q, e
	}
	if conf.Coolify == nil && conf.Harbor == nil {
		return q, serviceFailure(generated.ErrorCodePrerequisiteBlocked)
	}
	if e = c.applyOwnership(ctx, q, &conf); e != nil {
		return q, e
	}
	out, e := c.observe(ctx, q, conf, p, false)
	if e != nil {
		return q, e
	}
	q.ObservedDigest = out.ResultDigest
	return q, nil
}
func (c *hostingLifecycleComposition) Apply(ctx context.Context, q generated.HostingLifecycleRequest, actor identity.Principal) (hostinglifecycle.Outcome, error) {
	out := hostinglifecycle.Outcome{Status: "partial"}
	if !identity.ValidPrincipal(actor) {
		return out, serviceFailure(generated.ErrorCodeAuthenticationRequired)
	}
	ctx = identity.WithVerifiedPrincipal(ctx, actor)
	conf, p, e := c.configuration(ctx, q)
	if e != nil {
		return out, e
	}
	if e = c.applyOwnership(ctx, q, &conf); e != nil {
		return out, e
	}
	before, e := c.observe(ctx, q, conf, p, false)
	if e != nil {
		return out, e
	}
	if before.ResultDigest != q.ObservedDigest {
		return out, serviceFailure(generated.ErrorCodePlanStale)
	}
	return c.observe(ctx, q, conf, p, true)
}

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"slices"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
	"github.com/vegastack/vegastack-labs/internal/strictjson"
)

type controllerLoadedCredentialCheck func(context.Context, credentialref.LifecycleBinding) bool

// Only credentials declared for the existing manual delivery adapters may use
// the controller's already-loaded proof. This does not acknowledge a plan or
// replace the native positive/denied reader verification.
func controllerLoadedCredentials(p serverconfig.Profile, refs *store.CredentialRepository, gates *store.GateRepository, registry *adapter.Registry) controllerLoadedCredentialCheck {
	return func(ctx context.Context, b credentialref.LifecycleBinding) bool {
		if refs == nil || gates == nil || registry == nil {
			return false
		}
		ref, err := refs.GetCredentialVersion(ctx, b.ReferenceID, b.MaterialVersion)
		if err != nil {
			return false
		}
		scope, err := gates.GetAppliedProfileScope(ctx)
		if err != nil {
			return false
		}
		cap := declaredControllerCredentialCapability(ctx, p, scope, b, ref)
		if cap == "" || !slices.Contains(scope.Capabilities, cap) {
			return false
		}
		actual, err := registry.ResolveCredentialCapability("native-systemd", ref.ConsumerID, scope.ProfileID)
		return err == nil && actual == cap
	}
}

func declaredControllerCredentialCapability(ctx context.Context, p serverconfig.Profile, scope store.GateAppliedProfile, b credentialref.LifecycleBinding, ref generated.CredentialReference) string {
	if ctx == nil || ctx.Err() != nil || !credentialref.ValidLifecycleBinding(b) || b.HostActionConsole != nil || b.Action != credentialref.ActionActivate || b.ResolverID != "native-systemd" || len(b.ConsumerIDs) != 1 || len(b.NativeConsumers) != 1 || len(b.NativeDeniedReaders) == 0 || scope.StateRevision <= 0 || scope.StateRevision > b.StateRevision || scope.RecoveryEpoch != b.RecoveryEpoch {
		return ""
	}
	n := b.NativeConsumers[0]
	if n.UnitName != "vsk-labs.service" || n.ServiceUID != p.SocketOwnerUID || n.ProfileID != scope.ProfileID || n.RoleID != "control" || n.TargetID != b.TargetID || n.ConsumerID != b.ConsumerIDs[0] {
		return ""
	}
	if ref.ReferenceID != b.ReferenceID || ref.MaterialVersion != b.MaterialVersion || ref.ConsumerID != b.ConsumerIDs[0] || ref.TargetID != b.TargetID || ref.ResolverID != b.ResolverID || ref.RecoveryEpoch != b.RecoveryEpoch || ref.Status != "staged" || ref.Fingerprint != b.CiphertextFingerprint {
		return ""
	}
	match := func(id, consumer, purpose, cap string) string {
		if id != "" && ref.ReferenceID == id && ref.ConsumerID == consumer && ref.PurposeID == purpose {
			return cap
		}
		return ""
	}
	for _, h := range p.HostingLifecycleProfiles {
		if h.TargetID != b.TargetID {
			continue
		}
		raw, err := readLocalSetupProtected(ctx, h.ConfigurationPath, p.SocketOwnerUID, 1<<20)
		if err != nil || hostaction.BytesDigest(raw) != h.ConfigurationDigest {
			return ""
		}
		var conf hostingConfiguration
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if strictjson.Scan(ctx, raw, strictjson.Limits{MaxDepth: 24}) != nil || dec.Decode(&conf) != nil || dec.Decode(new(any)) != io.EOF {
			return ""
		}
		if conf.Harbor != nil {
			if c := match(conf.Harbor.ReferenceID, "registry.harbor.manage", "registry-manage", "credential.registry.manage"); c != "" {
				return c
			}
			for _, r := range conf.Harbor.Resources.Robots {
				if r.MaterialVersion != b.MaterialVersion {
					continue
				}
				consumer, purpose, cap := "registry.harbor.deploy", "registry-pull", "credential.registry.pull"
				if r.Push {
					consumer, purpose, cap = "registry.harbor.ci", "registry-push", "credential.registry.push"
				}
				if c := match(r.ReferenceID, consumer, purpose, cap); c != "" {
					return c
				}
			}
		}
		if conf.Coolify != nil {
			if c := match(h.MutationReferenceID, "hosting.coolify.deploy", "hosting-deploy", "credential.hosting.deploy"); c != "" {
				return c
			}
		}
	}
	for _, s := range p.ServiceBindings {
		if s.ServiceID != b.TargetID {
			continue
		}
		if s.Coolify != nil {
			if c := match(s.Coolify.ObservationReferenceID, "hosting.coolify", "hosting-observe", "credential.hosting.read"); c != "" {
				return c
			}
		}
		if s.Harbor != nil {
			if c := match(s.Harbor.ObservationReferenceID, "registry.harbor", "registry-observe", "credential.registry.read"); c != "" {
				return c
			}
		}
	}
	for _, d := range p.ServiceDeploymentBindings {
		if d.Binding.ServiceID != b.TargetID {
			continue
		}
		if c := match(d.MutationReferenceID, "hosting.coolify.deploy", "hosting-deploy", "credential.hosting.deploy"); c != "" {
			return c
		}
		if c := match(d.RuntimeReferenceID, "service.runtime", "runtime-observe", "credential.service-runtime.read"); c != "" {
			return c
		}
	}
	for _, m := range p.ManualPublicationBindings {
		if m.BindingID == b.TargetID && m.MaterialVersion == b.MaterialVersion {
			if c := match(m.ReferenceID, store.ManualPublicationAdapter, "artifact.publish.manual", "credential.registry.push"); c != "" {
				return c
			}
		}
	}
	return ""
}

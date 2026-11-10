//go:build linux

package server

import (
	"context"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/adapter/serviceruntime"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
)

func sharedCPUFixtureCapabilities(x *manualDeliveryCompositionFixture) []string {
	binding := x.f.source.bindings[x.f.definition.BindingID]
	return []string{manualServiceCapability(binding, x.db), manualSharedCPUCapability(binding, x.db), "credential.service-runtime.read"}
}

func TestManualSharedCPUAdmissionRequiresExactOptIn(t *testing.T) {
	for _, mode := range []string{"selected", "missing-extra", "missing-base", "wrong-extra", "strict-policy", "wrong-profile", "wrong-configuration", "wrong-identity", "wrong-epoch"} {
		t.Run(mode, func(t *testing.T) {
			x := newManualDeliveryCompositionFixture(t)
			caps := sharedCPUFixtureCapabilities(x)
			policy := "labs-working-manual"
			d, b, epoch := x.f.definition, x.db, int64(0)
			switch mode {
			case "missing-extra":
				caps = append(caps[:1], caps[2:]...)
			case "missing-base":
				caps = caps[1:]
			case "wrong-extra":
				caps[1] = "manual.service.shared-cpu.ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
			case "strict-policy":
				policy = "strict-policy"
			case "wrong-configuration":
				copy := *b.Configuration
				copy.Port++
				b.Configuration = &copy
			case "wrong-identity":
				d.HostIdentityDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
			case "wrong-epoch":
				epoch = 1
			}
			x.seedScope(caps, policy)
			if mode == "wrong-profile" {
				x.f.exec(`INSERT INTO gate_applied_profiles SELECT 'wrong-version',profile_id,'2.0.0',policy_id,policy_version,capabilities_bytes,state_revision+1,recovery_epoch,declaration_id,declaration_revision,plan_id,plan_digest,run_id,step_id,lease_id,human_id,applied_at FROM gate_applied_profiles ORDER BY state_revision DESC LIMIT 1`)
			}
			selected, e := x.deployment.sharedCPUAdmission(x.f.ctx, d, b, epoch)
			if mode == "selected" {
				if e != nil || !selected {
					t.Fatal("exact explicit shared CPU choice denied", selected, e)
				}
			} else if selected {
				t.Fatal("sharing escaped exact opt-in", mode, e)
			}
		})
	}
}

type sharedCapacityObserver struct {
	calls   int
	allowed bool
	change  func()
}

func (o *sharedCapacityObserver) Observe(context.Context, serviceruntime.Target, serviceruntime.Selection, *credentialref.Value, serviceruntime.Check) (serviceruntime.Snapshot, error) {
	return serviceruntime.Snapshot{}, serviceruntime.ErrUnavailable
}
func (o *sharedCapacityObserver) ObserveCapacity(ctx context.Context, target serviceruntime.Target, _ *credentialref.Value, check serviceruntime.Check) (serviceruntime.CapacitySnapshot, error) {
	o.calls++
	o.allowed = target.AllowSharedCPU
	if e := check(ctx); e != nil {
		return serviceruntime.CapacitySnapshot{}, e
	}
	if o.change != nil {
		o.change()
	}
	if e := check(ctx); e != nil {
		return serviceruntime.CapacitySnapshot{}, e
	}
	return serviceruntime.CapacitySnapshot{CPUQuotaPercent: 200, MemoryBytes: 536870912, StorageBytes: 2147483648, ObservedAt: time.Now().UTC().Format(time.RFC3339)}, nil
}

func TestManualSharedCPUCapacityRechecksBeforePersisting(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		name := "selected"
		if revoke {
			name = "revoked-only-shared-capability"
		}
		t.Run(name, func(t *testing.T) {
			x := newManualDeliveryCompositionFixture(t)
			f := x.f
			caps := sharedCPUFixtureCapabilities(x)
			x.seedScope(caps, "labs-working-manual")
			f.credentialVersion("runtime-ref", "service.runtime", "runtime-observe", "one", "active", 1)
			if e := f.source.registry.RegisterCredentialResolver(adapter.CredentialCapabilityScope{ResolverID: "fixture-service", ConsumerID: "service.runtime", ProfileID: "vegastack-labs", CapabilityID: "credential.service-runtime.read", Enabled: true}, manualRuntimeResolver{}); e != nil {
				t.Fatal(e)
			}
			observer := &sharedCapacityObserver{}
			if revoke {
				observer.change = func() { x.seedScope([]string{caps[0], caps[2]}, "labs-working-manual") }
			}
			x.deployment.runtime = observer
			out, e := x.deployment.observeCapacity(f.ctx, f.definition, x.db)
			if observer.calls != 1 || !observer.allowed {
				t.Fatal("exact opt-in not passed through actual observer target", observer.calls, observer.allowed, e)
			}
			var n int
			if err := f.db.QueryRow(`SELECT COUNT(*) FROM service_capacity_observations`).Scan(&n); err != nil {
				t.Fatal(err)
			}
			if revoke {
				if e == nil || n != 0 {
					t.Fatal("revoked shared capacity persisted or accepted", out, e, n)
				}
			} else if e != nil || n != 1 || out.CPUQuotaPercent != 200 {
				t.Fatal("current shared capacity not persisted", out, e, n)
			}
		})
	}
}

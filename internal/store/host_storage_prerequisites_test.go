package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/debianbaseline"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"testing"
	"time"
)

// Synthetic persisted native observations exercise the real migrated SQLite
// joins and denial rules. They are not proof that a real volume was qualified.
func TestHostStorageRequiresExactTwoCurrentReceipts(t *testing.T) {
	for _, mode := range []string{"success", "missing-recovery", "wrong-prior", "wrong-header", "failed-recovery", "unverified-step", "stale", "epoch", "custodian-identity", "failed-latest", "missing-declaration", "superseded-declaration"} {
		t.Run(mode, func(t *testing.T) {
			f, _, base := actionDraftFixture(t)
			exec := func(q string, a ...any) {
				t.Helper()
				if _, e := f.s.conn.ExecContext(f.ctx, q, a...); e != nil {
					t.Fatal(e)
				}
			}
			marshal := func(v any) []byte {
				b, e := json.Marshal(v)
				if e != nil {
					t.Fatal(e)
				}
				return b
			}
			d := hostaction.Digest("fixture-volume")
			now := f.s.config.Clock().UTC().Truncate(time.Second)
			custodianIdentity := hostaction.Digest("custodian-identity")
			target := discoveryFixtureTarget(t)
			target.TargetID = "custodian-target"
			dr := generated.HostDiscoveryTargetDraftRequest{Schema: generated.SchemaIDHostDiscoveryTargetDraftRequest, SchemaVersion: "1.0.0", Target: target, Action: "activate", IdempotencyKey: "custodian-target"}
			td := hostdiscovery.Digest(dr)
			exec(`INSERT INTO host_discovery_drafts VALUES('custodian-draft','custodian-target',1,0,'activate',?,?,'operator-a',0,0)`, td, marshal(dr))
			exec(`INSERT INTO host_discovery_targets VALUES('custodian-target',1,'custodian-draft','active','fixture-plan',0)`)
			exec(`INSERT INTO host_adoption_drafts VALUES('custodian-adoption',?,?,'operator-a',1,0)`, d, []byte(`{}`))
			exec(`INSERT INTO managed_hosts SELECT 'custodian','custodian-target',?,'product-serial','physical',observation_id,profile_id,'custodian-adoption',plan_id,approving_human_id,acknowledgement_id,state_revision,recovery_epoch FROM managed_hosts WHERE host_id='synthetic-host'`, custodianIdentity)
			binding := generated.HostVolumeBinding{Schema: generated.SchemaIDHostVolumeBinding, SchemaVersion: "1.0.0", HostID: base.HostID, HostIdentityDigest: base.ConsoleConfirmation.HostIdentityDigest, VolumeID: "data", ControlHostID: base.HostID, ControlHostIdentityDigest: base.ConsoleConfirmation.HostIdentityDigest, HeaderBytes: 4096, LUKSUUID: "12345678-1234-1234-1234-123456789abc", HeaderDigest: d, MappingDigest: d, MountBindingDigest: d, MapperName: "vsk-data", MountPath: "/srv/data", DeviceMajor: 253, DeviceMinor: 0, KeySlot: 1, RecoveryCustodianID: "custodian", RecoveryCustodianIdentityDigest: custodianIdentity, RecoveryTargetDigest: d, RecoveryReferenceDigest: d, DeclarationID: "volume-declaration", DeclarationRevision: 1, RecoveryEpoch: 0}
			lock := generated.DebianProfileLock{Schema: generated.SchemaIDDebianProfileLock, SchemaVersion: "1.0.0", ImageDigest: d, OSFamily: "debian", OSVersion: "13.6", Architecture: "amd64", PackageSourceDigest: d, Packages: []generated.AccessPackage{{Schema: generated.SchemaIDAccessPackage, SchemaVersion: "1.0.0", Name: "cryptsetup-bin", Version: "fixture"}}, ExecutableVersion: "1.0.0", AnsibleVersion: "fixture", AnsibleExecutableDigest: d, CollectionDigest: d, RoleDigest: d, Backend: "iptables-nft"}
			if mode == "custodian-identity" {
				binding.RecoveryCustodianIdentityDigest = hostaction.Digest("different-custodian")
			}
			in := generated.DebianBaselineInput{Schema: generated.SchemaIDDebianBaselineInput, SchemaVersion: "1.0.0", HostID: base.HostID, HostIdentityDigest: binding.HostIdentityDigest, ProfileID: "test-profile", ProfileLock: lock, ProfileLockDigest: hostaction.Digest(lock), RoleID: "host", ActionVersion: "1.0.0", AutomationUID: 1001, ControlIDs: []string{"linux.volume-encryption:data"}, RecoverySourcePrefixes: []string{"192.0.2.1/32"}, UpdateOwner: "operator", TimeOwner: "chrony", AuditPaths: []string{}, AppArmorProfiles: []generated.BaselineApparmorProfile{}, AIDE: generated.BaselineAidePolicy{Schema: generated.SchemaIDBaselineAidePolicy, SchemaVersion: "1.0.0", ScopePaths: []string{}, ScopeDigest: hostaction.Digest([]string{})}, Resources: []generated.BaselineResourceLimit{}, KernelSettings: []generated.BaselineKernelSetting{}, Volumes: []generated.HostVolumeBinding{binding}}
			in.RenderedPolicyDigest = debianbaseline.PolicyDigest(in)
			if mode != "missing-declaration" {
				declaration := generated.DeclarationRevision{Schema: generated.SchemaIDDeclarationRevision, SchemaVersion: "1.0.0", DeclarationID: binding.DeclarationID, DeclarationType: "host.volume", Revision: 1, StateRevision: 1, RecoveryEpoch: 0, Status: "draft", Operations: []generated.DeclarationOperation{{Sequence: 1, OperationID: "volume", OperationType: "host.action.execute", AdapterID: "host-action", TargetID: binding.HostID, InputDigest: hostaction.Digest(binding), ArtifactDigest: hostaction.Digest(binding)}}, CreatedAt: now.Format(time.RFC3339), CreatedBy: "operator-a", AgentSessionID: "fixture", Extensions: []generated.ContractExtension{{Name: "x-host-volume-binding", ValueDigest: hostaction.Digest(binding)}}}
				declaration.ContentDigest = declarationContentDigest(declaration, d)
				exec(`INSERT INTO declaration_revisions VALUES(?,?,'host.volume',1,0,?,?,'draft',?,'now','operator-a','fixture')`, declaration.DeclarationID, declaration.Revision, declaration.ContentDigest, d, marshal(declaration))
				if mode == "superseded-declaration" {
					declaration.Revision = 2
					declaration.ContentDigest = declarationContentDigest(declaration, d)
					exec(`INSERT INTO declaration_revisions VALUES(?,2,'host.volume',1,0,?,?,'draft',?,'now','operator-a','fixture')`, declaration.DeclarationID, declaration.ContentDigest, d, marshal(declaration))
				}
			}

			prior := ""
			serial := 0
			appendResult := func(kind string, req generated.HostActionRequest, b generated.HostVolumeBinding, status, stepState string) string {
				t.Helper()
				serial++
				suffix := fmt.Sprintf("%s-%d", kind, serial)
				scope, e := debianbaseline.ScopeForRequest(req)
				if e != nil {
					t.Fatal(e)
				}
				p := generated.Plan{PlanID: "volume-plan-" + suffix, PlanDigest: hostaction.Digest(suffix), HostAction: &req, HostBaselineScope: scope}
				p.Binding.RecoveryEpoch = 0
				at := now
				if mode == "stale" {
					at = at.Add(-11 * time.Minute)
				}
				m := generated.AccessMeasurement{Schema: generated.SchemaIDAccessMeasurement, SchemaVersion: "1.0.0", ControlID: scope.ControlIDs[0], Kind: "volume", Status: status, SubjectHostID: binding.HostID, SubjectIdentityDigest: binding.HostIdentityDigest, ProfileLockDigest: in.ProfileLockDigest, ProducerID: "debian-baseline", ProducerVersion: "1.0.0", BundleDigest: d, ObservedAt: at.Format(time.RFC3339), ConfigurationDigest: hostaction.Digest(b), PositiveProbeDigest: d, NegativeProbeDigest: hostaction.BytesDigest(nil), Reason: "synthetic-native-observation", Volume: &generated.VolumeObservation{Schema: generated.SchemaIDVolumeObservation, SchemaVersion: "1.0.0", Binding: b, Kind: kind, FactsDigest: d, PriorVolumeReceiptDigest: prior, ObservedAt: at.Format(time.RFC3339)}}

				if kind == "mapping" {
					wrong := m
					wrong.Volume = nil
					wrong.Kind = "baseline"
					wrong.ConfigurationDigest = req.ActionInputDigest
					wrong.Baseline = &generated.BaselineObservation{FactsDigest: d, Verification: "configuration-observed"}
					if validateBaselineMeasurement(p, wrong, 0) == nil {
						t.Fatal("volume action accepted baseline projection")
					}
					wrong = m
					copy := *m.Volume
					copy.Binding.VolumeID = "other"
					wrong.Volume = &copy
					wrong.ConfigurationDigest = hostaction.Digest(copy.Binding)
					other := in
					other.Volumes = append(append([]generated.HostVolumeBinding(nil), in.Volumes...), copy.Binding)
					other.RenderedPolicyDigest = debianbaseline.PolicyDigest(other)
					otherPlan := p
					otherReq := req
					otherReq.ActionInput = string(marshal(other))
					otherReq.ActionInputDigest = hostaction.BytesDigest([]byte(otherReq.ActionInput))
					otherPlan.HostAction = &otherReq
					if validateBaselineMeasurement(otherPlan, wrong, 0) == nil {
						t.Fatal("selected volume accepted different declared volume")
					}
				}
				m.MeasurementDigest = hostaction.MeasurementDigest(m)
				result := generated.HostActionResult{Schema: generated.SchemaIDHostActionResult, SchemaVersion: "1.0.0", BundleDigest: d, Status: "succeeded", Reason: "measured", ControlMeasurements: []generated.AccessMeasurement{m}}
				result.ResultDigest = hostaction.ResultDigest(result)
				if e := hostaction.ValidateResult(result); e != nil {
					t.Fatal(e)
				}
				receipt := generated.ExecutionReceipt{ReceiptID: "volume-receipt-" + suffix, ResultDigest: result.ResultDigest}
				rr := marshal(receipt)
				runID := "volume-run-" + suffix
				stepID := "volume-step-" + suffix
				leaseID := "volume-lease-" + suffix
				exec(`INSERT INTO immutable_plans VALUES(?,?,'fixture-declaration',1,1,0,?,?,?,?,?,?,'2026-01-01T00:00:00Z','2026-12-01T00:00:00Z')`, p.PlanID, p.PlanDigest, d, hostaction.Digest(p.PlanID), d, marshal(p), "fixture", d)
				exec(`INSERT INTO plan_runs VALUES(?,?,?,'decision',NULL,'1.0.0','central','executor',?,'succeeded',0,'not-requested','verified',?,0,0,0,?,?,?,'now','now')`, runID, p.PlanID, p.PlanDigest, d, d, hostaction.Digest(runID), d, []byte(`{}`))
				exec(`INSERT INTO plan_run_steps(step_id,run_id,sequence,operation_id,operation_type,adapter_id,executor_id,target_id,input_digest,artifact_digest,idempotent,status,effect_state,active_lease_id,result_digest,started_at,finished_at) VALUES(?,?,1,'volume','host.action.execute','host-action-ssh','executor',?,?,?,1,'succeeded',?,?,?,'now','now')`, stepID, runID, req.HostID, d, d, stepState, leaseID, result.ResultDigest)
				exec(`INSERT INTO target_execution_leases(lease_id,run_id,step_id,target_id,binding_digest,nonce_digest,recovery_epoch,claimed_at,renew_after,expires_at,maximum_expires_at,status,canonical_bytes) VALUES(?,?,?,?,?,?,0,'now','later','later','later','released',?)`, leaseID, runID, stepID, req.HostID, d, d, []byte(`{}`))
				exec(`INSERT INTO execution_receipts VALUES(?,?,?,?,'succeeded',?,?,'now')`, receipt.ReceiptID, leaseID, runID, stepID, result.ResultDigest, rr)
				exec(`INSERT INTO host_control_results VALUES(?,?,?,0,?,?,?,?,?,?,?,0,?,?,?,?,?,?,?,?,?)`, runID, stepID, result.ResultDigest, p.PlanID, p.PlanDigest, d, "volume", req.HostID, binding.HostID, binding.HostIdentityDigest, receipt.ReceiptID, hostaction.BytesDigest(rr), m.ControlID, status, m.ObservedAt, m.MeasurementDigest, marshal(m), []byte(`{}`), marshal(result))
				return hostaction.BytesDigest(rr)
			}
			req := base
			req.ActionID = "debian.volume.observe"
			req.ActionInput = string(marshal(in))
			req.ActionInputDigest = hostaction.BytesDigest([]byte(req.ActionInput))
			prior = appendResult("mapping", req, binding, "passed", "verified")
			if mode != "missing-recovery" {
				recovery := generated.VolumeRecoveryInput{Schema: generated.SchemaIDVolumeRecoveryInput, SchemaVersion: "1.0.0", HostID: "custodian", HostIdentityDigest: binding.RecoveryCustodianIdentityDigest, ProfileID: in.ProfileID, ProfileLock: lock, ProfileLockDigest: in.ProfileLockDigest, RoleID: "host", ActionVersion: "1.0.0", AutomationUID: 1001, Binding: binding, PriorVolumeReceiptDigest: prior, RecoveryReferenceID: "recovery-key", RecoveryMaterialVersion: "version-a"}
				if mode == "wrong-prior" {
					prior = d
					recovery.PriorVolumeReceiptDigest = d
				}
				b := binding
				if mode == "wrong-header" {
					b.HeaderDigest = hostaction.Digest("wrong-header")
					recovery.Binding = b
				}
				req = base
				req.HostID = "custodian"
				req.TargetDigest = td
				req.ConsoleConfirmation.TargetDigest = td
				req.ConsoleConfirmation.HostIdentityDigest = binding.RecoveryCustodianIdentityDigest
				req.ActionID = "debian.volume-recovery.verify"
				req.ActionInput = string(marshal(recovery))
				req.ActionInputDigest = hostaction.BytesDigest([]byte(req.ActionInput))
				status, state := "passed", "verified"
				if mode == "failed-recovery" {
					status = "failed"
				}
				if mode == "unverified-step" {
					state = "receipt-recorded"
				}
				appendResult("recovery", req, b, status, state)
				if mode == "failed-latest" {
					appendResult("recovery", req, b, "failed", "verified")
				}
			}
			if mode == "epoch" {
				exec(`UPDATE system_meta SET recovery_epoch=1 WHERE id=1`)
			}
			if mode == "success" || mode == "stale" || mode == "missing-recovery" {
				admission := HostAdmissionSnapshot{Host: generated.ManagedHost{HostID: base.HostID}, Revision: RevisionToken{RecoveryEpoch: 0}, Measurements: []HostAdmissionMeasurement{{Measurement: generated.AccessMeasurement{Volume: &generated.VolumeObservation{Binding: binding}}}}}
				err := f.s.Read(f.ctx, func(tx ReadTx) error { return admissionVolumeDeclarations(f.ctx, tx, &admission, now) })
				if err != nil || len(admission.Blockers) != 0 {
					t.Fatalf("role-only storage blocked baseline: %v %+v", err, admission.Blockers)
				}
				if mode == "success" && len(admission.RoleBlockers) != 0 {
					t.Fatal("current storage pair role blocked", admission.RoleBlockers)
				}
				if mode != "success" && len(admission.RoleBlockers) == 0 {
					t.Fatal("missing or expired recovery lost role blocker", mode)
				}
			}
			got, e := NewGateRepository(f.s).ResolveHostStoragePrerequisites(f.ctx, base.HostID, []string{"data"}, now)
			if mode == "success" {
				if e != nil || len(got.VolumeEvidenceDigests) != 1 || len(got.RecoveryEvidenceDigests) != 1 {
					t.Fatalf("exact pair rejected: %+v %v", got, e)
				}
			} else if e == nil {
				t.Fatalf("unsafe %s accepted", mode)
			}
		})
	}
}

func TestBaselineScopeUsesCanonicalSubjectRoleAuthorization(t *testing.T) {
	f, _, _ := actionDraftFixture(t)
	exec := func(q string, a ...any) {
		t.Helper()
		if _, e := f.s.conn.ExecContext(f.ctx, q, a...); e != nil {
			t.Fatal(e)
		}
	}
	d := hostaction.Digest("authorization-fixture")
	_, e := f.s.executeAuditIntent(f.ctx, discoveryIntent(f.attr, "run.created", "baseline-auth-run", d, d), false, func(context.Context, *sql.Tx) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	for _, host := range []string{"synthetic-host", "custodian"} {
		exec(`INSERT OR IGNORE INTO effective_authorization_grants VALUES(?,'operator-a','control-plane-admin','acknowledge','plan.acknowledge','plan-target',?,'human',1,'active','now','now')`, "baseline-ack-"+host, host)
		role := "infrastructure-admin"
		if host == "synthetic-host" {
			role = "maintainer"
		}
		exec(`INSERT INTO effective_authorization_grants VALUES(?,'operator-a',?,'execute','host.action.execute','execution-target',?,'human',1,'active','now','now')`, "baseline-exec-"+host, role, host)
	}
	p := generated.Plan{PlanID: "baseline-auth-plan", PlanDigest: d, Risk: "infrastructure", AuthorizationBranch: "human", Operations: []generated.PlanOperation{{Sequence: 1, OperationType: "host.action.execute", TargetID: "custodian"}}, HostBaselineScope: &generated.HostBaselineScope{SubjectHostID: "synthetic-host", ExecutionHostID: "custodian"}}
	if e := f.s.conn.QueryRowContext(f.ctx, `SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&p.Binding.StateRevision, &p.Binding.RecoveryEpoch); e != nil {
		t.Fatal(e)
	}
	row := func(q string, a ...any) *sql.Row { return f.s.conn.QueryRowContext(f.ctx, q, a...) }
	if authorizeBaselineScope(f.ctx, row, p, "baseline-auth-run", "operator-a") == nil {
		t.Fatal("subject maintainer bypassed infrastructure role")
	}
	exec(`UPDATE effective_authorization_grants SET status='revoked' WHERE grant_id='baseline-exec-synthetic-host'`)
	exec(`INSERT INTO effective_authorization_grants VALUES('baseline-exec-subject-admin','operator-a','infrastructure-admin','execute','host.action.execute','execution-target','synthetic-host','human',1,'active','now','now')`)
	if e := authorizeBaselineScope(f.ctx, row, p, "baseline-auth-run", "operator-a"); e != nil {
		t.Fatal("valid subject and custodian admins denied", e)
	}
}

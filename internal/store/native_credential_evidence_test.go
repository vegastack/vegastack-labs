package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"strings"
	"testing"
)

func TestNativeCredentialProjectionRejectsSubstitutedControllerAndReceipt(t *testing.T) {
	for _, variant := range []string{"actual", "machine", "run", "missing-receipt", "missing-denial"} {
		t.Run(variant, func(t *testing.T) {
			s := portableDiscoveryStore(t)
			ctx := context.Background()
			d := hostaction.Digest("native")
			machine := strings.Repeat("a", 32)
			authority, err := s.CurrentAuthority(ctx)
			if err != nil {
				t.Fatal(err)
			}
			b := credentialref.LifecycleBinding{OperationID: "activate-a", Action: credentialref.ActionActivate, ReferenceID: "reference-a", ConsumerIDs: []string{"consumer-a"}, RequiredDeniedConsumerIDs: []string{"denied-a"}, NativeArtifactConsumerID: "consumer-a", MaterialVersion: "version-a", ResolverID: "native-systemd", TargetID: "target-a", CiphertextFingerprint: d, StateRevision: 1, RecoveryEpoch: authority.RecoveryEpoch}
			b.NativeConsumers = []credentialref.NativeConsumerBinding{{ConsumerID: "consumer-a", TargetID: b.TargetID, HostMachineID: machine, UnitName: "a.service", ServiceUID: 1001, ServiceGID: 1001, ProfileID: "profile-a", RoleID: "role-a", LoadedName: credentialref.LoadedNameForVersion("consumer-a", b.ReferenceID, b.MaterialVersion)}}
			b.NativeDeniedReaders = []credentialref.NativeDeniedReaderBinding{{ConsumerID: "denied-a", TargetID: b.TargetID, HostMachineID: machine, ReaderUID: 2001, ReaderGID: 2001, ProfileID: "profile-b", RoleID: "denied"}}
			body, _ := json.Marshal(b)
			digest := credentialref.LifecycleManifestDigestOf(b)
			if _, err = s.conn.ExecContext(ctx, `INSERT INTO credential_lifecycle_bindings(binding_id,declaration_id,declaration_revision,operation_id,action,reference_id,binding_digest,binding_bytes,recovery_epoch,created_at) VALUES('binding-a','declaration-a',1,'activate-a','credential.activate','reference-a',?,?,?,'2026-10-09T00:00:00Z')`, digest, body, authority.RecoveryEpoch); err != nil {
				t.Fatal(err)
			}
			if _, err = s.conn.ExecContext(ctx, `INSERT INTO credential_reference_versions(version_id,reference_id,consumer_id,purpose_id,target_id,resolver_id,material_version,fingerprint,status,state_revision,recovery_epoch,activated_at,verified_consumers_bytes,declaration_id,declaration_revision,plan_id,plan_digest,run_id,step_id,lease_id,human_id,created_at) VALUES('version-row','reference-a','consumer-a','purpose-a','target-a','native-systemd','version-a',?,'active',1,?,'2026-10-09T00:00:00Z',?,'declaration-a',2,'plan-a',?,'run-a','step-a','lease-a','human-a','2026-10-09T00:00:00Z')`, d, authority.RecoveryEpoch, []byte(`["consumer-a"]`), d); err != nil {
				t.Fatal(err)
			}
			receipt := credentialref.NativeLoadedReceipt{Version: 1, Binding: b, ConsumerID: "consumer-a", PlanDigest: d, RunID: "run-a", StepID: "step-a", Proof: credentialref.NativeInvocationMetadata{BootID: "00000000-0000-0000-0000-000000000001", InvocationID: strings.Repeat("b", 32), MainPID: 42, ProcessStartTicks: 7, NamespaceDevice: 1, NamespaceInode: 2, CredentialDevice: 3, CredentialInode: 4, CredentialUID: 1001, CredentialGID: 1001, CredentialMode: 0100400, SourceDevice: 5, SourceInode: 6, SourceFingerprint: d}}
			if variant == "run" {
				receipt.RunID = "other-run"
			}
			positive, err := credentialref.NewConsumerVerification(b, "consumer-a", "profile-a", "role-a", d, "native-systemd-delivery", "verified", true)
			if err != nil {
				t.Fatal(err)
			}
			positive.NativeReceipt = &receipt
			if variant == "missing-receipt" {
				positive.NativeReceipt = nil
			}
			denied, err := credentialref.NewConsumerVerification(b, "denied-a", "profile-b", "denied", d, "reader-denied", "denied", false)
			if err != nil {
				t.Fatal(err)
			}
			for _, v := range []credentialref.ConsumerVerification{positive, denied} {
				if variant == "missing-denial" && v.Result == "denied" {
					continue
				}
				var native any
				if v.NativeReceipt != nil {
					native, err = credentialref.EncodeNativeLoadedReceipt(*v.NativeReceipt)
					if err != nil {
						t.Fatal(err)
					}
				}
				if _, err = s.conn.ExecContext(ctx, `INSERT INTO credential_consumer_verifications(verification_id,reference_id,version_id,consumer_id,profile_id,role_id,material_version,ciphertext_fingerprint,evidence_digest,restart_observed,result,reason_code,recovery_epoch,created_at,native_receipt_bytes) VALUES(?,'reference-a','version-row',?,?,?,?,?,?,?,?,?,?,'2026-10-09T00:00:00Z',?)`, v.ConsumerID, v.ConsumerID, v.ProfileID, v.RoleID, v.MaterialVersion, v.CiphertextFingerprint, v.EvidenceDigest, v.RestartObserved, v.Result, v.ReasonCode, authority.RecoveryEpoch, native); err != nil {
					t.Fatal(err)
				}
			}
			c := generated.NativeControllerIdentity{Schema: generated.SchemaIDNativeControllerIdentity, SchemaVersion: "1.0.0", HostID: "controller", HostIdentityDigest: d, HostMachineID: machine, ControllerInstanceID: authority.InstanceID, ScopeDigest: d, ExecutableDigest: d}
			if variant == "machine" {
				c.HostMachineID = strings.Repeat("c", 32)
			}
			repo := NewGateRepository(s).WithNativeControllerIdentity(c)
			e := NativeProducerExecution{Reference: generated.NativeProducerReference{HostID: "controller", PlanID: "plan-a", PlanDigest: d, RunID: "run-a", StepID: "step-a", LeaseID: "lease-a"}, Plan: generated.Plan{DeclarationID: "declaration-a", Binding: generated.PlanBinding{DeclarationRevision: 2, StateRevision: 1}, Extensions: []generated.ContractExtension{{Name: "x-credential-lifecycle", ValueDigest: digest}}}, Receipt: generated.ExecutionReceipt{OperationID: "activate-a", AdapterID: "core.credential", TargetID: "target-a", ArtifactDigest: d, Status: "succeeded", RecoveryEpoch: authority.RecoveryEpoch}}
			err = s.Read(ctx, func(tx ReadTx) error {
				q := nativeQuery{tx: tx, row: func(query string, a ...any) *sql.Row { return tx.queryRow(ctx, query, a...) }, rows: func(query string, a ...any) (*sql.Rows, error) { return tx.query(ctx, query, a...) }}
				_, err := repo.nativeCredentialEvidence(ctx, q, e, d)
				return err
			})
			if variant == "actual" && err != nil {
				t.Fatal(err)
			}
			if variant != "actual" && err == nil {
				t.Fatal("substituted proof accepted")
			}
		})
	}
}

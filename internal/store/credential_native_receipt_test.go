package store

import (
	"context"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
)

func TestNativeReceiptStoreLegacyAndRevocation(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "actual-receipt", true: "legacy-without-receipt"}[legacy], func(t *testing.T) {
			s := portableDiscoveryStore(t)
			repo := NewCredentialRepository(s)
			ctx := context.Background()
			if _, err := s.conn.ExecContext(ctx, `UPDATE system_meta SET state_revision=1 WHERE id=1`); err != nil {
				t.Fatal(err)
			}
			revision, err := NewPlanRepository(s).CurrentRevision(ctx)
			if err != nil {
				t.Fatal(err)
			}
			fp := "sha256:" + strings.Repeat("a", 64)
			b := credentialref.LifecycleBinding{OperationID: "activate-a", Action: credentialref.ActionActivate, ReferenceID: "reference-a", ConsumerIDs: []string{"consumer-a"}, RequiredDeniedConsumerIDs: []string{"denied-a"}, NativeArtifactConsumerID: "consumer-a", MaterialVersion: "version-a", ResolverID: "native-systemd", TargetID: "target-a", CiphertextFingerprint: fp, StateRevision: revision.StateRevision, RecoveryEpoch: revision.RecoveryEpoch}
			b.NativeConsumers = []credentialref.NativeConsumerBinding{{ConsumerID: "consumer-a", TargetID: b.TargetID, HostMachineID: strings.Repeat("a", 32), UnitName: "a.service", ServiceUID: 1001, ServiceGID: 1001, ProfileID: "profile-a", RoleID: "role-a", LoadedName: credentialref.LoadedNameForVersion("consumer-a", b.ReferenceID, b.MaterialVersion)}}
			b.NativeDeniedReaders = []credentialref.NativeDeniedReaderBinding{{ConsumerID: "denied-a", TargetID: b.TargetID, HostMachineID: strings.Repeat("a", 32), ReaderUID: 2001, ReaderGID: 2001, ProfileID: "profile-a", RoleID: "role-denied"}}
			receipt := credentialref.NativeLoadedReceipt{Version: 1, Binding: b, ConsumerID: "consumer-a", PlanDigest: fp, RunID: "run-a", StepID: "step-a", Proof: credentialref.NativeInvocationMetadata{BootID: "00000000-0000-0000-0000-000000000001", InvocationID: strings.Repeat("b", 32), MainPID: 42, ProcessStartTicks: 7, NamespaceDevice: 1, NamespaceInode: 2, CredentialDevice: 3, CredentialInode: 4, CredentialUID: 1001, CredentialGID: 1001, CredentialMode: 0100400, SourceDevice: 5, SourceInode: 6, SourceFingerprint: fp}}
			insertVersion := func(id, status string, rev int64) {
				t.Helper()
				_, err := s.conn.ExecContext(ctx, `INSERT INTO credential_reference_versions(version_id,reference_id,consumer_id,purpose_id,target_id,resolver_id,material_version,fingerprint,status,state_revision,recovery_epoch,activated_at,verified_consumers_bytes,declaration_id,declaration_revision,plan_id,plan_digest,run_id,step_id,lease_id,human_id,created_at) VALUES(?,'reference-a','consumer-a','purpose-a','target-a','native-systemd','version-a',?,?,?,?,'2026-10-09T00:00:00Z',?,'declaration-a',1,'plan-a',?,'run-a','step-a','lease-a','human-a','2026-10-09T00:00:00Z')`, id, fp, status, rev, revision.RecoveryEpoch, []byte(`["consumer-a"]`), fp)
				if err != nil {
					t.Fatal(err)
				}
			}
			insertVersion("v-active", "active", revision.StateRevision)
			verification, err := credentialref.NewConsumerVerification(b, "consumer-a", "profile-a", "role-a", fp, "native-systemd-delivery", "verified", true)
			if err != nil {
				t.Fatal(err)
			}
			if !legacy {
				verification.NativeReceipt = &receipt
			}
			if !legacy {
				badTx, err := s.conn.BeginTx(ctx, nil)
				if err != nil {
					t.Fatal(err)
				}
				err = repo.consumerVerificationExtra(b, []credentialref.ConsumerVerification{verification}, CredentialStageRequest{PlanDigest: fp, RunID: "wrong-run", StepID: "step-a"})(ctx, badTx, "v-active", "2026-10-09T00:00:00Z")
				_ = badTx.Rollback()
				if err == nil {
					t.Fatal("receipt from another lifecycle run persisted")
				}
			}
			tx, err := s.conn.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			err = repo.consumerVerificationExtra(b, []credentialref.ConsumerVerification{verification}, CredentialStageRequest{PlanDigest: fp, RunID: "run-a", StepID: "step-a"})(ctx, tx, "v-active", "2026-10-09T00:00:00Z")
			if err != nil {
				_ = tx.Rollback()
				t.Fatal(err)
			}
			if err = tx.Commit(); err != nil {
				t.Fatal(err)
			}
			step := credentialref.StepBinding{OperationID: "execute-a", AdapterID: "adapter-a", TargetID: b.TargetID, ReferenceID: b.ReferenceID, ConsumerID: "consumer-a", PurposeID: "purpose-a", MaterialVersion: b.MaterialVersion, ResolverID: b.ResolverID, StateRevision: revision.StateRevision, RecoveryEpoch: revision.RecoveryEpoch}
			got, err := repo.ReadNativeLoadedReceipt(ctx, step)
			if legacy {
				if err == nil {
					t.Fatal("legacy generic digest promoted")
				}
				return
			}
			if err != nil || got.Proof != receipt.Proof {
				t.Fatal("actual receipt not retained", err)
			}
			insertVersion("v-revoked", "revoked", revision.StateRevision+1)
			if _, err := repo.ReadNativeLoadedReceipt(ctx, step); err == nil {
				t.Fatal("revoked material retained loaded authority")
			}
		})
	}
}

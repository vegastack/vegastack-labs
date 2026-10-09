//go:build linux

package qualification

import (
	"bytes"
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"os"
	"path/filepath"
	"testing"
)

func TestNativePreparationLookupAndFixtureApprovalStayFinite(t *testing.T) {
	scope, err := validateScope(scopeFixture())
	if err != nil {
		t.Fatal(err)
	}
	binding := generated.NativeStepRequest{Operation: "prepare", GuestID: "subject", ScenarioID: "baseline-access", RecoveryEpoch: 0}
	lookup := generated.NativePreparationRequest{Binding: binding, Kind: "producer-lookup", ProducerLookup: &generated.NativeProducerLookupRequest{ScopeDigest: scope.digest, ScenarioID: binding.ScenarioID, HostID: scope.guests["subject"].HostID}}
	if validatePreparation(scope, lookup) != nil {
		t.Fatal("lookup rejected")
	}
	for _, variant := range []string{"host", "scope", "scenario", "epoch", "mixed"} {
		t.Run(variant, func(t *testing.T) {
			bad := lookup
			v := *lookup.ProducerLookup
			bad.ProducerLookup = &v
			switch variant {
			case "host":
				v.HostID = "outside"
			case "scope":
				v.ScopeDigest = "other"
			case "scenario":
				v.ScenarioID = "role-ci"
			case "epoch":
				v.RecoveryEpoch = 1
			case "mixed":
				bad.Identifier = "caller-path"
			}
			if validatePreparation(scope, bad) == nil {
				t.Fatal("lookup escaped binding")
			}
		})
	}
	approval := generated.NativePreparationRequest{Binding: binding, Kind: "fixture-approval", FixtureApproval: &generated.NativeSlackFixtureApproval{RecoveryEpoch: 0}}
	if validatePreparation(scope, approval) != nil {
		t.Fatal("approval rejected")
	}
	approval.Identifier = "caller-human"
	if validatePreparation(scope, approval) == nil {
		t.Fatal("extra authority accepted")
	}
}

func TestPreparationCannotMixRequestsOrChangeScopedHost(t *testing.T) {
	scope, err := validateScope(scopeFixture())
	if err != nil {
		t.Fatal(err)
	}
	in := generated.NativePreparationRequest{Schema: generated.SchemaIDNativePreparationRequest, SchemaVersion: "1.0.0", Binding: generated.NativeStepRequest{Operation: "prepare", GuestID: "subject", RecoveryEpoch: 0}, Kind: "action", Action: &generated.HostActionRequest{HostID: scope.guests["subject"].HostID, RecoveryEpoch: 0}}
	if err = validatePreparation(scope, in); err != nil {
		t.Fatal(err)
	}
	for _, variant := range []string{"extra-identifier", "extra-action", "other-host", "other-epoch", "raw-command", "unknown-guest"} {
		t.Run(variant, func(t *testing.T) {
			bad := in
			a := *in.Action
			bad.Action = &a
			switch variant {
			case "extra-identifier":
				bad.Identifier = "another-plan"
			case "extra-action":
				bad.Discovery = &generated.HostDiscoveryRequest{}
			case "other-host":
				bad.Action.HostID = "outside"
			case "other-epoch":
				bad.Action.RecoveryEpoch = 1
			case "raw-command":
				bad.Kind = "shell"
			case "unknown-guest":
				bad.Binding.GuestID = "outside"
			}
			if validatePreparation(scope, bad) == nil {
				t.Fatal("broadened preparation admitted")
			}
		})
	}
}

func TestRecoveryPreparationCannotEscapeScopeOrMixInputs(t *testing.T) {
	scope, err := validateScope(scopeFixture())
	if err != nil {
		t.Fatal(err)
	}
	hosts := []string{}
	for _, g := range scope.guests {
		hosts = append(hosts, g.HostID)
	}
	in := generated.NativePreparationRequest{Binding: generated.NativeStepRequest{Operation: "prepare", GuestID: "subject", RecoveryEpoch: 0}, Kind: "restore-plan", RestorePlan: &generated.RestoreRequest{RecoveryEpoch: 0, FormerHostID: hosts[0], ReplacementHostID: hosts[1]}}
	if validatePreparation(scope, in) != nil {
		t.Fatal("scoped restore rejected")
	}
	for _, variant := range []string{"outside", "same-host", "epoch", "mixed"} {
		t.Run(variant, func(t *testing.T) {
			bad := in
			q := *in.RestorePlan
			bad.RestorePlan = &q
			switch variant {
			case "outside":
				q.ReplacementHostID = "outside"
			case "same-host":
				q.ReplacementHostID = q.FormerHostID
			case "epoch":
				q.RecoveryEpoch = 1
			case "mixed":
				bad.BackupRun = &generated.BackupRunRequest{}
			}
			if validatePreparation(scope, bad) == nil {
				t.Fatal("broadened restore accepted")
			}
		})
	}
	for _, kind := range []string{"backup-policy", "backup-run", "backup-verify", "restore-run", "restore-verify"} {
		bad := in
		bad.Kind = kind
		if validatePreparation(scope, bad) == nil {
			t.Fatal("missing/mixed payload accepted", kind)
		}
	}
}

func TestNativeGrantAndStatusPreparationStayScoped(t *testing.T) {
	scope, err := validateScope(scopeFixture())
	if err != nil {
		t.Fatal(err)
	}
	binding := generated.NativeStepRequest{Operation: "prepare", GuestID: "subject", RecoveryEpoch: 0}
	in := generated.NativePreparationRequest{Binding: binding, Kind: "grant-batch", GrantBatch: &generated.AuthorizationGrantBatchRequest{PrincipalID: "existing-human", Changes: []generated.AuthorizationGrantChange{{ResourceID: scope.guests["subject"].HostID}}}}
	if validatePreparation(scope, in) != nil {
		t.Fatal("named grant rejected")
	}
	for _, variant := range []string{"outside", "epoch", "mixed", "missing"} {
		t.Run(variant, func(t *testing.T) {
			bad := in
			batch := *in.GrantBatch
			batch.Changes = append([]generated.AuthorizationGrantChange{}, batch.Changes...)
			bad.GrantBatch = &batch
			switch variant {
			case "outside":
				batch.Changes[0].ResourceID = "outside"
			case "epoch":
				batch.RecoveryEpoch = 1
			case "mixed":
				bad.Identifier = "caller-path"
			case "missing":
				bad.GrantBatch = nil
			}
			if validatePreparation(scope, bad) == nil {
				t.Fatal("broadened grant accepted")
			}
		})
	}
	status := generated.NativePreparationRequest{Binding: binding, Kind: "database-status"}
	if validatePreparation(scope, status) != nil {
		t.Fatal("status rejected")
	}
	status.GrantBatch = in.GrantBatch
	if validatePreparation(scope, status) == nil {
		t.Fatal("status accepted payload")
	}
}

func TestBootstrapPreparationRequiresScopedProfileAndProtectedCredentialSlot(t *testing.T) {
	s, err := validateScope(scopeFixture())
	if err != nil {
		t.Fatal(err)
	}
	b := generated.NativeStepRequest{Operation: "prepare", GuestID: "subject", RecoveryEpoch: 0}
	p := generated.NativePreparationRequest{Binding: b, Kind: "profile", Profile: &generated.GateProfileDraftRequest{ProfileID: s.value.ProfileID, RecoveryEpoch: 0}}
	if validatePreparation(s, p) != nil {
		t.Fatal("scoped profile rejected")
	}
	bad := p
	q := *p.Profile
	q.ProfileID = "outside"
	bad.Profile = &q
	if validatePreparation(s, bad) == nil {
		t.Fatal("outside profile accepted")
	}
	q = *p.Profile
	q.RecoveryEpoch = 1
	bad.Profile = &q
	if validatePreparation(s, bad) == nil {
		t.Fatal("stale profile epoch accepted")
	}
	g := s.guests[b.GuestID]
	c := generated.NativePreparationRequest{Binding: b, Kind: "credential-import", CredentialSlot: g.Role + "-ssh", CredentialImport: &generated.CredentialImportRequest{ReferenceID: "native-ssh-" + g.HostID, TargetID: g.HostID, ConsumerID: hostaction.AdapterID, PurposeID: hostaction.PurposeID, ResolverID: "native-systemd", RecoveryEpoch: 0}}
	if validatePreparation(s, c) != nil {
		t.Fatal("scoped credential rejected")
	}
	for _, variant := range []string{"slot", "host", "reference", "resolver", "consumer", "purpose", "epoch", "mixed", "absent"} {
		t.Run(variant, func(t *testing.T) {
			bad := c
			v := *c.CredentialImport
			bad.CredentialImport = &v
			switch variant {
			case "slot":
				bad.CredentialSlot = "../../secret"
			case "host":
				v.TargetID = "outside"
			case "reference":
				v.ReferenceID = "unrelated"
			case "resolver":
				v.ResolverID = "external"
			case "consumer":
				v.ConsumerID = "other"
			case "purpose":
				v.PurposeID = "other"
			case "epoch":
				v.RecoveryEpoch = 1
			case "mixed":
				bad.Profile = p.Profile
			case "absent":
				bad.CredentialImport = nil
			}
			if validatePreparation(s, bad) == nil {
				t.Fatal("credential scope widened")
			}
		})
	}
	p.CredentialSlot = g.Role + "-ssh"
	if validatePreparation(s, p) == nil {
		t.Fatal("unused slot accepted")
	}
}

func TestFixtureImportMaterialProtectedLocalFiles(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires the actual nonroot service identity")
	}
	uid := uint32(os.Geteuid())
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "native-ssh-subject")
	material := []byte("synthetic-private-material-for-software-test")
	if err := os.WriteFile(path, material, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readFixtureImportMaterialAt(context.Background(), root, uid, "subject-ssh")
	if err != nil || !bytes.Equal(got, material) {
		t.Fatal("prepared private material unavailable", err)
	}
	for i := range got {
		got[i] = 0
	}
	for _, variant := range []string{"unknown-slot", "root-identity", "wrong-identity", "loose-directory", "loose-file", "symlink-file", "symlink-directory", "missing-file"} {
		t.Run(variant, func(t *testing.T) {
			useRoot, useUID, slot := root, uid, "subject-ssh"
			switch variant {
			case "unknown-slot":
				slot = "/other/secret"
			case "root-identity":
				useUID = 0
			case "wrong-identity":
				useUID = uid + 1
			case "loose-directory":
				if os.Chmod(root, 0755) != nil {
					t.Fatal("chmod")
				}
				defer os.Chmod(root, 0700)
			case "loose-file":
				if os.Chmod(path, 0644) != nil {
					t.Fatal("chmod")
				}
				defer os.Chmod(path, 0600)
			case "symlink-file":
				if os.Rename(path, path+".saved") != nil || os.Symlink(path+".saved", path) != nil {
					t.Fatal("link")
				}
				defer func() { os.Remove(path); os.Rename(path+".saved", path) }()
			case "symlink-directory":
				useRoot = root + "-link"
				if os.Symlink(root, useRoot) != nil {
					t.Fatal("link")
				}
				defer os.Remove(useRoot)
			case "missing-file":
				slot = "current-ssh"
			}
			b, e := readFixtureImportMaterialAt(context.Background(), useRoot, useUID, slot)
			if e == nil || len(b) != 0 {
				t.Fatal("private material boundary escaped")
			}
		})
	}
}

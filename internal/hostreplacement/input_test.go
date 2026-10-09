package hostreplacement

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"golang.org/x/crypto/ssh"
)

func fixture() generated.HostReplacementRequest {
	d := func(s string) string { return hostaction.BytesDigest([]byte(s)) }
	return generated.HostReplacementRequest{
		Schema: generated.SchemaIDHostReplacementRequest, SchemaVersion: "1.0.0", ReplacementID: "replacement-a", Operation: "freeze", RestorationClass: "stateless-role",
		OldHostID: "old-host", NewHostID: "new-host", OldIdentityDigest: d("old"), NewIdentityDigest: d("new"), OldTargetDigest: d("old-target"), NewTargetDigest: d("new-target"), OldSSHHostKeyDigest: d("old-key"), NewSSHHostKeyDigest: d("new-key"), OldTargetRevision: 1, NewTargetRevision: 1,
		ProfileID: "profile", ProfileLockDigest: d("profile"), OldRoleBindingDigest: d("old-role"), RoleDeclarationID: "old-role", RoleDeclarationRevision: 1, ProposedRoleDeclarationID: "new-role", ProposedRoleDeclarationRevision: 1, ProposedRoleBindingDigest: d("new-role"), PreservedPreimageDigest: d("preimage"),
		AliasBindings: []generated.HostReplacementAliasBinding{{Schema: generated.SchemaIDHostReplacementAliasBinding, SchemaVersion: "1.0.0", AliasID: "alias-a", OwnerHostID: "old-host", OwnerIdentityDigest: d("old"), OwnerRevision: 1, OwnershipGeneration: 1}}, PayloadIDs: []string{}, VolumeIDs: []string{}, ResourceIDs: []string{},
		OSPreparation: generated.HostReplacementOsPreparation{Schema: generated.SchemaIDHostReplacementOsPreparation, SchemaVersion: "1.0.0", Method: "administrator-prepared", ObservationID: "observation-a", ObservationDigest: d("observation"), HostIdentityDigest: d("new"), ConfirmedAt: "2026-10-09T12:00:00Z"}, ExpectedStateRevision: 1, RecoveryEpoch: 0, IdempotencyKey: "freeze-a",
	}
}
func TestReplacementFiniteInput(t *testing.T) {
	good := fixture()
	if err := ValidateInput(good); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*generated.HostReplacementRequest){
		"same-host":         func(r *generated.HostReplacementRequest) { r.NewHostID = r.OldHostID },
		"same-identity":     func(r *generated.HostReplacementRequest) { r.NewIdentityDigest = r.OldIdentityDigest },
		"same-key":          func(r *generated.HostReplacementRequest) { r.NewSSHHostKeyDigest = r.OldSSHHostKeyDigest },
		"protected":         func(r *generated.HostReplacementRequest) { r.NewHostID = "vsk-node-04" },
		"wrong-alias-owner": func(r *generated.HostReplacementRequest) { r.AliasBindings[0].OwnerHostID = "another" },
		"duplicate-alias": func(r *generated.HostReplacementRequest) {
			r.AliasBindings = append(r.AliasBindings, r.AliasBindings[0])
		},
		"mixed-generation": func(r *generated.HostReplacementRequest) {
			a := r.AliasBindings[0]
			a.AliasID = "alias-b"
			a.OwnershipGeneration++
			r.AliasBindings = append(r.AliasBindings, a)
		},
		"unsorted":          func(r *generated.HostReplacementRequest) { r.ResourceIDs = []string{"resource-b", "resource-a"} },
		"case-collision":    func(r *generated.HostReplacementRequest) { r.ResourceIDs = []string{"RESOURCE-A", "resource-a"} },
		"unowned-payload":   func(r *generated.HostReplacementRequest) { r.PayloadIDs = []string{"app-data"} },
		"missing-source":    func(r *generated.HostReplacementRequest) { r.RestorationClass = "control-database" },
		"wrong-os-identity": func(r *generated.HostReplacementRequest) { r.OSPreparation.HostIdentityDigest = r.OldIdentityDigest },
		"unknown-operation": func(r *generated.HostReplacementRequest) { r.Operation = "erase" },
		"oversized":         func(r *generated.HostReplacementRequest) { r.ResourceIDs = make([]string, 33) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := fixture()
			mutate(&r)
			if ValidateInput(r) == nil {
				t.Fatal("invalid replacement accepted")
			}
		})
	}
	raw, _ := json.Marshal(good)
	for _, bad := range [][]byte{append(raw, []byte("{}")...), bytes.Replace(raw, []byte(`"operation":"freeze"`), []byte(`"operation":"freeze","operation":"commit"`), 1), bytes.Replace(raw, []byte(`"operation":"freeze"`), []byte(`"operation":"freeze","destinationPath":"/tmp"`), 1), bytes.Repeat([]byte(" "), MaximumInput+1)} {
		if _, e := DecodeInput(bad); e == nil {
			t.Fatal("nonexact JSON accepted")
		}
	}
}
func TestReplacementBindingSeparatesIntentFromAttempt(t *testing.T) {
	r := fixture()
	base := BindingDigest(r)
	r.Operation = "commit"
	r.ExpectedStateRevision++
	r.ExpectedDeclarationRevision++
	r.IdempotencyKey = "commit-a"
	if BindingDigest(r) != base {
		t.Fatal("procedural attempt changed intent")
	}
	for name, mutate := range map[string]func(*generated.HostReplacementRequest){"key": func(r *generated.HostReplacementRequest) {
		r.NewSSHHostKeyDigest = hostaction.BytesDigest([]byte("changed"))
	}, "epoch": func(r *generated.HostReplacementRequest) { r.RecoveryEpoch++ }, "role": func(r *generated.HostReplacementRequest) { r.ProposedRoleDeclarationRevision++ }, "alias": func(r *generated.HostReplacementRequest) { r.AliasBindings[0].OwnerRevision++ }} {
		t.Run(name, func(t *testing.T) {
			r := fixture()
			mutate(&r)
			if BindingDigest(r) == base {
				t.Fatal("authority change did not change intent")
			}
		})
	}
}
func TestControlSourceAndAliasClaim(t *testing.T) {
	r := fixture()
	r.RestorationClass = "control-database"
	r.Source = &generated.HostReplacementSourceReference{Schema: generated.SchemaIDHostReplacementSourceReference, SchemaVersion: "1.0.0", PointID: "point-a", CustodyReferenceID: "recovery-draft", ManifestDigest: hostaction.BytesDigest([]byte("manifest")), SourceBindingDigest: hostaction.BytesDigest([]byte("source")), CustodyBindingDigest: hostaction.BytesDigest([]byte("custody"))}
	if ValidateInput(r) != nil {
		t.Fatal("exact source rejected")
	}
	r.RestorationClass = "stateless-role"
	if ValidateInput(r) == nil {
		t.Fatal("stateless accepted source")
	}
	c := generated.HostAliasClaimRequest{Schema: generated.SchemaIDHostAliasClaimRequest, SchemaVersion: "1.0.0", HostID: "host-a", HostIdentityDigest: r.NewIdentityDigest, AliasIDs: []string{"alias-a"}, IdempotencyKey: "claim-a"}
	if ValidateAliasClaim(c) != nil {
		t.Fatal("claim rejected")
	}
	c.AliasIDs = []string{"alias-a", "alias-a"}
	if ValidateAliasClaim(c) == nil {
		t.Fatal("duplicate claim accepted")
	}
}
func TestSSHKeyDigestUsesCanonicalPublicMaterial(t *testing.T) {
	key, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)).Public())
	if err != nil {
		t.Fatal(err)
	}
	raw := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	a, err := SSHHostKeyDigest(raw)
	if err != nil {
		t.Fatal(err)
	}
	b, err := SSHHostKeyDigest(raw + " comment")
	if err != nil || a != b || a != hostaction.BytesDigest(key.Marshal()) {
		t.Fatal("digest not canonical")
	}
	for _, bad := range []string{"not-a-key", raw + "\n" + raw, `command="id" ` + raw} {
		if _, err := SSHHostKeyDigest(bad); err == nil {
			t.Fatal("ambiguous key accepted")
		}
	}
}

func TestOptionalReplacementReferencesPreserveLegacyOmission(t *testing.T) {
	for _, v := range []any{generated.Plan{}, generated.RestoreRequest{}, generated.RestoreBinding{}, generated.DeclarationRevisionRequest{}, generated.DeclarationRevision{}} {
		raw, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		for _, name := range []string{"hostReplacement", "hostAliasClaim", "replacementContinuity"} {
			if bytes.Contains(raw, []byte(`"`+name+`"`)) {
				t.Fatalf("absent replacement field changed legacy bytes: %s", name)
			}
		}
	}
}

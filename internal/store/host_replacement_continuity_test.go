package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostreplacement"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"strconv"
	"testing"
)

func testHostReplacementContinuity(t *testing.T, source ...generated.RestoreSourceBinding) HostReplacementContinuity {
	t.Helper()
	digest := hostaction.Digest
	q := generated.HostReplacementRequest{Schema: generated.SchemaIDHostReplacementRequest, SchemaVersion: "1.0.0", ReplacementID: "replacement-a", Operation: "freeze", RestorationClass: "control-database", OldHostID: "old-host", NewHostID: "new-host", OldIdentityDigest: digest("old"), NewIdentityDigest: digest("new"), OldTargetDigest: digest("old-target"), NewTargetDigest: digest("new-target"), OldSSHHostKeyDigest: digest("old-key"), NewSSHHostKeyDigest: digest("new-key"), OldTargetRevision: 1, NewTargetRevision: 1, ProfileID: "profile", ProfileLockDigest: digest("profile"), OldRoleBindingDigest: digest("old-role"), RoleDeclarationID: "old-role", RoleDeclarationRevision: 1, ProposedRoleDeclarationID: "new-role", ProposedRoleDeclarationRevision: 1, ProposedRoleBindingDigest: digest("new-role"), PreservedPreimageDigest: digest("preimage"), PayloadIDs: []string{}, VolumeIDs: []string{}, ResourceIDs: []string{}, OSPreparation: generated.HostReplacementOsPreparation{Schema: generated.SchemaIDHostReplacementOsPreparation, SchemaVersion: "1.0.0", Method: "administrator-prepared", ObservationID: "observation-a", ObservationDigest: digest("observation"), HostIdentityDigest: digest("new"), ConfirmedAt: "2026-10-09T12:00:00Z"}, ExpectedStateRevision: 1, IdempotencyKey: "freeze-a"}
	q.Source = &generated.HostReplacementSourceReference{Schema: generated.SchemaIDHostReplacementSourceReference, SchemaVersion: "1.0.0", PointID: "point-a", ManifestDigest: digest("manifest"), SourceBindingDigest: digest("source"), CustodyReferenceID: "custody-a", CustodyBindingDigest: digest("custody")}
	if len(source) > 0 {
		q.Source.PointID = source[0].PointID
		q.Source.ManifestDigest = source[0].ManifestDigest
		q.Source.SourceBindingDigest = digest(source[0])
	}
	a := generated.HostReplacementAliasBinding{Schema: generated.SchemaIDHostReplacementAliasBinding, SchemaVersion: "1.0.0", AliasID: "alias-a", OwnerHostID: q.OldHostID, OwnerIdentityDigest: q.OldIdentityDigest, OwnerRevision: 1, OwnershipGeneration: 1}
	q.AliasBindings = []generated.HostReplacementAliasBinding{a}
	if err := hostreplacement.ValidateInput(q); err != nil {
		t.Fatal(err)
	}
	d := HostReplacementDraft{Request: q, Digest: digest(q), BindingDigest: hostreplacement.BindingDigest(q)}
	d.ID = "host-replacement-" + d.Digest[7:39]
	x := HostReplacementExecution{ReplacementID: q.ReplacementID, DraftID: d.ID, PlanID: "plan-a", PlanDigest: digest("plan"), RunID: "run-a", StepID: "step-a", LeaseID: "lease-a"}
	first := HostAliasEvent{Ordinal: 1, Alias: a, Execution: HostReplacementExecution{DraftID: "claim-a"}, StateRevision: 1}
	frozen := first
	frozen.Ordinal = 2
	frozen.Alias.OwnerRevision = 2
	frozen.PreviousDigest = digest(first)
	frozen.ReplacementID = q.ReplacementID
	frozen.Execution = x
	state := replacementState(d)
	state.Status = "frozen"
	state.NextAction = "resolve-fences"
	state.AliasBindings = []generated.HostReplacementAliasBinding{frozen.Alias}
	event := HostReplacementEvent{ReplacementID: q.ReplacementID, Sequence: 1, Type: "frozen", Execution: x, State: state, AuthorityDigest: digest("authority"), At: "2026-10-09T12:00:00Z"}
	c := HostReplacementContinuity{Reference: generated.HostReplacementContinuityReference{Schema: generated.SchemaIDHostReplacementContinuityReference, SchemaVersion: "1.0.0", ReplacementID: q.ReplacementID, SourcePointID: q.Source.PointID, SourceBindingDigest: q.Source.SourceBindingDigest, CurrentAliasHighWatermark: 2}, Drafts: []HostReplacementDraft{d}, Events: []HostReplacementEvent{event}, Aliases: []HostAliasEvent{first, frozen}, Owners: []HostAliasOwner{{Alias: frozen.Alias, EventDigest: digest(frozen), FrozenReplacementID: q.ReplacementID}}}
	c.Reference.Digest = HostReplacementContinuityDigest(c)
	if err := validateReplacementContinuity(c); err != nil {
		t.Fatal(err)
	}
	return c
}
func TestReplacementContinuityMergesFrozenHistoryAndRejectsTamper(t *testing.T) {
	for _, mode := range []string{"complete", "omitted-delta", "changed-owner", "newer-destination"} {
		t.Run(mode, func(t *testing.T) {
			s := portableDiscoveryStore(t)
			c := testHostReplacementContinuity(t)
			if mode == "omitted-delta" {
				c.Aliases = c.Aliases[:1]
				c.Reference.Digest = HostReplacementContinuityDigest(c)
			}
			if mode == "changed-owner" {
				c.Owners[0].Alias.OwnerHostID = "attacker"
				c.Reference.Digest = HostReplacementContinuityDigest(c)
			}
			tx, err := s.conn.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if mode == "newer-destination" {
				e := c.Aliases[0]
				e.Ordinal = 3
				if err = insertAliasEvent(context.Background(), tx, e); err != nil {
					t.Fatal(err)
				}
			}
			err = mergeReplacementContinuity(context.Background(), tx, c)
			if mode != "complete" {
				if err == nil {
					t.Fatal("invalid continuity accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			row := func(q string, a ...any) *sql.Row { return tx.QueryRowContext(context.Background(), q, a...) }
			if requireHostUnfrozen(row, "old-host") == nil {
				t.Fatal("recovered freeze missing")
			}
			if err = mergeReplacementContinuity(context.Background(), tx, c); err != nil {
				t.Fatal("identical continuity not idempotent", err)
			}
			if _, err = tx.Exec(`UPDATE host_alias_history SET owner_revision=99`); err == nil {
				t.Fatal("history mutable")
			}
			if err = tx.Commit(); err != nil {
				t.Fatal(err)
			}
			n, err := s.HostAliasHighWatermark(context.Background())
			if err != nil || n != 2 {
				t.Fatal(n, err)
			}
		})
	}
}
func TestReplacementFreezeBlocksActionBeforeCredentialIssuance(t *testing.T) {
	s := portableDiscoveryStore(t)
	c := testHostReplacementContinuity(t)
	tx, err := s.conn.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = mergeReplacementContinuity(context.Background(), tx, c); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	err = s.Read(context.Background(), func(tx ReadTx) error {
		_, err := actionTarget(func(q string, a ...any) *sql.Row { return tx.queryRow(context.Background(), q, a...) }, generated.HostActionRequest{HostID: "old-host"})
		return err
	})
	if Code(err) != generated.ErrorCodePrerequisiteBlocked {
		t.Fatal("frozen old host reached action validation", err)
	}
}
func TestReplacementFreezeDeniesCredentialReservationAndAppend(t *testing.T) {
	s := portableDiscoveryStore(t)
	tx, err := s.conn.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := mergeReplacementContinuity(context.Background(), tx, testHostReplacementContinuity(t)); err != nil {
		t.Fatal(err)
	}
	for _, action := range []credentialref.LifecycleAction{credentialref.ActionStage, credentialref.ActionActivate, credentialref.ActionRotate, credentialref.ActionRecover} {
		t.Run(string(action), func(t *testing.T) {
			p := generated.Plan{Operations: []generated.PlanOperation{{OperationType: string(action), TargetID: "old-host"}}}
			if err := validateReplacementReservation(context.Background(), tx, p); Code(err) != generated.ErrorCodePrerequisiteBlocked {
				t.Fatal("reservation", err)
			}
			r := NewCredentialRepository(s)
			request := CredentialLifecycleApplyRequest{Binding: credentialref.LifecycleBinding{Action: action, TargetID: "old-host"}}
			if err := r.lifecycleAppendExtra(request, nil)(context.Background(), tx, "version", "now"); Code(err) != generated.ErrorCodePrerequisiteBlocked {
				t.Fatal("append", err)
			}
		})
	}
	p := generated.Plan{Operations: []generated.PlanOperation{{OperationType: string(credentialref.ActionRevoke), TargetID: "old-host"}}}
	if err := validateReplacementReservation(context.Background(), tx, p); err != nil {
		t.Fatal("revocation reservation blocked", err)
	}
}
func TestReplacementRejectsSameIdentity(t *testing.T) {
	s := portableDiscoveryStore(t)
	q := testHostReplacementContinuity(t).Drafts[0].Request
	q.NewHostID = q.OldHostID
	if _, err := NewHostReplacementRepository(s).Stage(context.Background(), q, HostReplacementExecution{}.Attribution); err == nil {
		t.Fatal("same identity accepted")
	}
}
func cloneReplacementContinuity(t *testing.T, c HostReplacementContinuity) HostReplacementContinuity {
	t.Helper()
	raw, _ := json.Marshal(c)
	var copy HostReplacementContinuity
	if json.Unmarshal(raw, &copy) != nil {
		t.Fatal("clone")
	}
	return copy
}

func TestReplacementAliasCASHasOneWinnerAndPreservesHistory(t *testing.T) {
	s := portableDiscoveryStore(t)
	c := testHostReplacementContinuity(t)
	tx, err := s.conn.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = mergeReplacementContinuity(context.Background(), tx, c); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var winners int
	principal, _ := identity.PrincipalFromContext(discoveryPrincipalContext())
	attribution, e := audit.NewAttribution(principal, &principal, nil)
	if e != nil {
		t.Fatal(e)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	for attempt := 0; attempt < 2; attempt++ {
		go func(attempt int) {
			<-start
			state := c.Events[0].State
			state.AliasBindings = append([]generated.HostReplacementAliasBinding(nil), state.AliasBindings...)
			_, e := s.executeAuditIntent(context.Background(), discoveryIntent(attribution, "host.alias.cas-test", "alias-a", hostaction.Digest(strconv.Itoa(attempt)), hostaction.Digest(c)), false, func(ctx context.Context, tx *sql.Tx) error {
				return commitReplacementAliases(ctx, tx, c.Events[0].Execution, c.Drafts[0].Request, generated.Plan{}, &state)
			})
			results <- e
		}(attempt)
	}
	close(start)
	for i := 0; i < 2; i++ {
		if e := <-results; e == nil {
			winners++
		}
	}

	if winners != 1 {
		t.Fatal("CAS winners", winners)
	}
	var owner string
	var revision, history int
	if err = s.conn.QueryRowContext(context.Background(), `SELECT owner_host_id,owner_revision FROM host_alias_owners WHERE alias_id='alias-a'`).Scan(&owner, &revision); err != nil {
		t.Fatal(err)
	}
	if err = s.conn.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM host_alias_history WHERE alias_id='alias-a'`).Scan(&history); err != nil {
		t.Fatal(err)
	}
	if owner != "new-host" || revision != 3 || history != 3 {
		t.Fatal(owner, revision, history)
	}
	var frozen int
	if err = s.conn.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM host_replacement_events WHERE old_host_id='old-host' AND event_type='frozen'`).Scan(&frozen); err != nil || frozen != 1 {
		t.Fatal("old frozen history lost", err)
	}
}

func TestReplacementAliasCASRollsBackEveryAliasOnConflict(t *testing.T) {
	s := portableDiscoveryStore(t)
	c := testHostReplacementContinuity(t)
	tx, err := s.conn.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = mergeReplacementContinuity(context.Background(), tx, c); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	request := c.Drafts[0].Request
	second := request.AliasBindings[0]
	second.AliasID = "missing-alias"
	request.AliasBindings = append(append([]generated.HostReplacementAliasBinding(nil), request.AliasBindings...), second)
	state := c.Events[0].State
	state.AliasBindings = append(append([]generated.HostReplacementAliasBinding(nil), state.AliasBindings...), second)
	p, _ := identity.PrincipalFromContext(discoveryPrincipalContext())
	attribution, _ := audit.NewAttribution(p, &p, nil)
	_, err = s.executeAuditIntent(context.Background(), discoveryIntent(attribution, "host.alias.cas-test", "alias-a", hostaction.Digest("multi"), hostaction.Digest(request)), false, func(ctx context.Context, tx *sql.Tx) error {
		return commitReplacementAliases(ctx, tx, c.Events[0].Execution, request, generated.Plan{}, &state)
	})
	if err == nil {
		t.Fatal("missing second owner accepted")
	}
	var owner string
	var history int
	if err = s.conn.QueryRowContext(context.Background(), `SELECT owner_host_id FROM host_alias_owners WHERE alias_id='alias-a'`).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	if err = s.conn.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM host_alias_history`).Scan(&history); err != nil {
		t.Fatal(err)
	}
	if owner != "old-host" || history != 2 {
		t.Fatal("partial alias transition committed", owner, history)
	}
}

func TestReplacementRejectsDifferentRoleIntentWithSameBinding(t *testing.T) {
	q := testHostReplacementContinuity(t).Drafts[0].Request
	p := generated.Plan{DeclarationID: "different-role-declaration", Binding: generated.PlanBinding{DeclarationRevision: q.ProposedRoleDeclarationRevision + 1, StateRevision: 9}, HostAction: &generated.HostActionRequest{}, HostRoleScope: &generated.HostRoleScope{SubjectHostID: q.NewHostID, SubjectIdentityDigest: q.NewIdentityDigest, RoleBindingDigest: q.ProposedRoleBindingDigest, ProfileLockDigest: q.ProfileLockDigest}}
	declaration := generated.DeclarationRevision{DeclarationID: q.ProposedRoleDeclarationID, Revision: q.ProposedRoleDeclarationRevision, Status: "draft"}
	if err := validateReplacementRoleIntentPlan(p, declaration, q, 9); Code(err) != generated.ErrorCodePlanStale {
		t.Fatal("other declaration substituted identical role binding", err)
	}
}

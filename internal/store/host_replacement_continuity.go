package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostreplacement"
	"sort"
)

type HostAliasOwner struct {
	Alias               generated.HostReplacementAliasBinding
	EventDigest         string
	FrozenReplacementID string
}
type HostReplacementContinuity struct {
	Reference generated.HostReplacementContinuityReference
	Drafts    []HostReplacementDraft
	Events    []HostReplacementEvent
	Aliases   []HostAliasEvent
	Owners    []HostAliasOwner
}

func HostReplacementContinuityDigest(c HostReplacementContinuity) string {
	c.Reference.Digest = ""
	return hostaction.Digest(c)
}
func (s *Store) HostAliasHighWatermark(ctx context.Context) (n int64, err error) {
	err = s.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT COALESCE(MAX(event_ordinal),0) FROM host_alias_history`).Scan(&n)
	})
	return
}
func (s *Store) LoadHostReplacementContinuity(ctx context.Context, replacementID string, reference generated.HostReplacementContinuityReference) (out HostReplacementContinuity, err error) {
	out.Reference = reference
	if reference.ReplacementID != replacementID || reference.SourceAliasHighWatermark < 0 || reference.SourcePointID == "" || reference.SourceBindingDigest == "" {
		return out, replacementError(generated.ErrorCodeInputInvalid)
	}
	err = s.Read(ctx, func(tx ReadTx) error {
		row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
		if e := row(`SELECT COALESCE(MAX(event_ordinal),0) FROM host_alias_history`).Scan(&out.Reference.CurrentAliasHighWatermark); e != nil {
			return e
		}
		if reference.SourceAliasHighWatermark > out.Reference.CurrentAliasHighWatermark {
			return replacementError(generated.ErrorCodePlanStale)
		}
		var id string
		if e := row(`SELECT draft_id FROM host_replacement_drafts WHERE replacement_id=? AND operation='freeze'`, replacementID).Scan(&id); e != nil {
			return e
		}
		draft, e := readReplacementDraft(row, id)
		if e != nil {
			return e
		}
		if draft.Request.Source == nil || draft.Request.Source.PointID != reference.SourcePointID || draft.Request.Source.SourceBindingDigest != reference.SourceBindingDigest {
			return replacementError(generated.ErrorCodePlanStale)
		}
		for _, host := range []string{draft.Request.OldHostID, draft.Request.NewHostID} {
			if _, e = adoptionGrant(ctx, row, host, "host", "read", "host.read", false); e != nil {
				return e
			}
		}
		aliases := map[string]bool{}
		replacements := map[string]bool{replacementID: true}
		for _, a := range draft.Request.AliasBindings {
			aliases[a.AliasID] = true
		}
		rows, e := tx.query(ctx, `SELECT DISTINCT alias_id FROM host_alias_history WHERE event_ordinal>? ORDER BY alias_id`, reference.SourceAliasHighWatermark)
		if e != nil {
			return e
		}
		for rows.Next() {
			var id string
			if e = rows.Scan(&id); e != nil {
				rows.Close()
				return e
			}
			aliases[id] = true
			if len(aliases) > 32 {
				rows.Close()
				return replacementError(generated.ErrorCodePrerequisiteBlocked)
			}
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		ids := make([]string, 0, len(aliases))
		for id := range aliases {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, aliasID := range ids {
			var owner HostAliasOwner
			var freeze sql.NullString
			owner.Alias.Schema = generated.SchemaIDHostReplacementAliasBinding
			owner.Alias.SchemaVersion = "1.0.0"
			owner.Alias.AliasID = aliasID
			if e = row(`SELECT owner_host_id,owner_identity_digest,owner_revision,ownership_generation,event_digest,frozen_replacement_id FROM host_alias_owners WHERE alias_id=?`, aliasID).Scan(&owner.Alias.OwnerHostID, &owner.Alias.OwnerIdentityDigest, &owner.Alias.OwnerRevision, &owner.Alias.OwnershipGeneration, &owner.EventDigest, &freeze); e != nil {
				return e
			}
			if freeze.Valid {
				owner.FrozenReplacementID = freeze.String
				replacements[freeze.String] = true
			}
			out.Owners = append(out.Owners, owner)
			rows, e = tx.query(ctx, `SELECT event_bytes,event_digest FROM host_alias_history WHERE alias_id=? ORDER BY event_ordinal`, aliasID)
			if e != nil {
				return e
			}
			for rows.Next() {
				var raw []byte
				var digest string
				var event HostAliasEvent
				if e = rows.Scan(&raw, &digest); e != nil {
					rows.Close()
					return e
				}
				if json.Unmarshal(raw, &event) != nil || hostaction.Digest(event) != digest {
					rows.Close()
					return replacementError(generated.ErrorCodeIntegrityFailure)
				}
				out.Aliases = append(out.Aliases, event)
				if event.ReplacementID != "" {
					replacements[event.ReplacementID] = true
				}
				if len(out.Aliases) > 256 {
					rows.Close()
					return replacementError(generated.ErrorCodePrerequisiteBlocked)
				}
			}
			e = rows.Err()
			rows.Close()
			if e != nil {
				return e
			}
		}
		sort.Slice(out.Aliases, func(i, j int) bool { return out.Aliases[i].Ordinal < out.Aliases[j].Ordinal })
		replacementIDs := make([]string, 0, len(replacements))
		for id := range replacements {
			replacementIDs = append(replacementIDs, id)
		}
		sort.Strings(replacementIDs)
		for _, rid := range replacementIDs {
			rows, e = tx.query(ctx, `SELECT draft_id FROM host_replacement_drafts WHERE replacement_id=? ORDER BY operation`, rid)
			if e != nil {
				return e
			}
			draftIDs := []string{}
			for rows.Next() {
				var id string
				if e = rows.Scan(&id); e != nil {
					rows.Close()
					return e
				}
				draftIDs = append(draftIDs, id)
			}
			e = rows.Err()
			rows.Close()
			if e != nil {
				return e
			}
			for _, id := range draftIDs {
				d, e := readReplacementDraft(row, id)
				if e != nil {
					return e
				}
				out.Drafts = append(out.Drafts, d)
			}
			rows, e = tx.query(ctx, `SELECT event_bytes,event_digest FROM host_replacement_events WHERE replacement_id=? ORDER BY sequence`, rid)
			if e != nil {
				return e
			}
			for rows.Next() {
				var raw []byte
				var digest string
				var event HostReplacementEvent
				if e = rows.Scan(&raw, &digest); e != nil {
					rows.Close()
					return e
				}
				if json.Unmarshal(raw, &event) != nil || hostaction.Digest(event) != digest {
					rows.Close()
					return replacementError(generated.ErrorCodeIntegrityFailure)
				}
				out.Events = append(out.Events, event)
				if len(out.Events) > 256 {
					rows.Close()
					return replacementError(generated.ErrorCodePrerequisiteBlocked)
				}
			}
			e = rows.Err()
			rows.Close()
			if e != nil {
				return e
			}
		}
		out.Reference.Digest = HostReplacementContinuityDigest(out)
		return validateReplacementContinuity(out)
	})
	return
}
func validateReplacementContinuity(c HostReplacementContinuity) error {
	raw, _ := json.Marshal(c)
	if len(raw) > 4194304 || len(c.Owners) == 0 || len(c.Owners) > 32 || len(c.Aliases) == 0 || len(c.Aliases) > 256 || len(c.Events) == 0 || len(c.Events) > 256 || c.Reference.Digest != HostReplacementContinuityDigest(c) || c.Reference.CurrentAliasHighWatermark < c.Reference.SourceAliasHighWatermark {
		return replacementError(generated.ErrorCodeIntegrityFailure)
	}
	next := c.Reference.SourceAliasHighWatermark + 1
	last := int64(0)
	byAlias := map[string]HostAliasEvent{}
	for _, event := range c.Aliases {
		if event.Ordinal <= last || event.Alias.OwnerRevision < 1 || event.Ordinal > c.Reference.CurrentAliasHighWatermark {
			return replacementError(generated.ErrorCodeIntegrityFailure)
		}
		last = event.Ordinal
		if event.Ordinal > c.Reference.SourceAliasHighWatermark {
			if event.Ordinal != next {
				return replacementError(generated.ErrorCodeIntegrityFailure)
			}
			next++
		}
		prior, ok := byAlias[event.Alias.AliasID]
		if ok {
			if event.Alias.OwnerRevision != prior.Alias.OwnerRevision+1 || event.PreviousDigest != hostaction.Digest(prior) {
				return replacementError(generated.ErrorCodeIntegrityFailure)
			}
		} else if event.Alias.OwnerRevision != 1 || event.PreviousDigest != "" {
			return replacementError(generated.ErrorCodeIntegrityFailure)
		}
		byAlias[event.Alias.AliasID] = event
	}
	if next != c.Reference.CurrentAliasHighWatermark+1 {
		return replacementError(generated.ErrorCodeIntegrityFailure)
	}
	owners := map[string]bool{}
	for _, owner := range c.Owners {
		last, ok := byAlias[owner.Alias.AliasID]
		if !ok || owners[owner.Alias.AliasID] || hostaction.Digest(last.Alias) != hostaction.Digest(owner.Alias) || hostaction.Digest(last) != owner.EventDigest {
			return replacementError(generated.ErrorCodeIntegrityFailure)
		}
		owners[owner.Alias.AliasID] = true
	}
	if len(owners) != len(byAlias) {
		return replacementError(generated.ErrorCodeIntegrityFailure)
	}
	drafts := map[string]HostReplacementDraft{}
	for _, d := range c.Drafts {
		if hostreplacement.ValidateInput(d.Request) != nil || hostaction.Digest(d.Request) != d.Digest || d.ID != "host-replacement-"+d.Digest[7:39] {
			return replacementError(generated.ErrorCodeIntegrityFailure)
		}
		drafts[d.Request.ReplacementID] = d
	}
	frozen := false
	for _, e := range c.Events {
		if _, ok := drafts[e.ReplacementID]; !ok {
			return replacementError(generated.ErrorCodeIntegrityFailure)
		}
		if e.ReplacementID == c.Reference.ReplacementID && e.Type == "frozen" {
			frozen = true
		}
	}
	if !frozen {
		return replacementError(generated.ErrorCodePrerequisiteBlocked)
	}
	return nil
}
func mergeReplacementContinuity(ctx context.Context, tx *sql.Tx, c HostReplacementContinuity) error {
	if e := validateReplacementContinuity(c); e != nil {
		return e
	}
	var maximum int64
	if e := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(event_ordinal),0) FROM host_alias_history`).Scan(&maximum); e != nil {
		return e
	}
	if maximum != c.Reference.SourceAliasHighWatermark && maximum != c.Reference.CurrentAliasHighWatermark {
		return replacementError(generated.ErrorCodeStateConflict)
	}
	for _, d := range c.Drafts {
		raw, _ := json.Marshal(d.Request)
		var digest string
		e := tx.QueryRowContext(ctx, `SELECT content_digest FROM host_replacement_drafts WHERE draft_id=?`, d.ID).Scan(&digest)
		if e == nil {
			if digest != d.Digest {
				return replacementError(generated.ErrorCodeIntegrityFailure)
			}
			continue
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		if hostaction.Digest(d.Request) != d.Digest {
			return replacementError(generated.ErrorCodeIntegrityFailure)
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO host_replacement_drafts VALUES(?,?,?,?,?,?,?,?,?)`, d.ID, d.Request.ReplacementID, d.Request.Operation, d.BindingDigest, d.Digest, raw, "recovered-continuity", d.Request.ExpectedStateRevision, d.Request.RecoveryEpoch); e != nil {
			return e
		}
	}
	for _, event := range c.Events {
		var digest string
		e := tx.QueryRowContext(ctx, `SELECT event_digest FROM host_replacement_events WHERE replacement_id=? AND sequence=?`, event.ReplacementID, event.Sequence).Scan(&digest)
		if e == nil {
			if digest != hostaction.Digest(event) {
				return replacementError(generated.ErrorCodeIntegrityFailure)
			}
			continue
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		if _, e = insertReplacementEvent(ctx, tx, event); e != nil {
			return e
		}
	}
	for _, event := range c.Aliases {
		var digest string
		e := tx.QueryRowContext(ctx, `SELECT event_digest FROM host_alias_history WHERE event_ordinal=?`, event.Ordinal).Scan(&digest)
		if e == nil {
			if digest != hostaction.Digest(event) {
				return replacementError(generated.ErrorCodeIntegrityFailure)
			}
			continue
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		if event.Ordinal <= c.Reference.SourceAliasHighWatermark {
			return replacementError(generated.ErrorCodeIntegrityFailure)
		}
		if e = insertAliasEvent(ctx, tx, event); e != nil {
			return e
		}
	}
	for _, owner := range c.Owners {
		var rev int64
		var digest string
		e := tx.QueryRowContext(ctx, `SELECT owner_revision,event_digest FROM host_alias_owners WHERE alias_id=?`, owner.Alias.AliasID).Scan(&rev, &digest)
		if e == nil && rev > owner.Alias.OwnerRevision {
			return replacementError(generated.ErrorCodeStateConflict)
		}
		if e == nil && rev == owner.Alias.OwnerRevision && digest != owner.EventDigest {
			return replacementError(generated.ErrorCodeIntegrityFailure)
		}
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO host_alias_owners VALUES(?,?,?,?,?,?,?) ON CONFLICT(alias_id) DO UPDATE SET owner_host_id=excluded.owner_host_id,owner_identity_digest=excluded.owner_identity_digest,owner_revision=excluded.owner_revision,ownership_generation=excluded.ownership_generation,event_digest=excluded.event_digest,frozen_replacement_id=excluded.frozen_replacement_id`, owner.Alias.AliasID, owner.Alias.OwnerHostID, owner.Alias.OwnerIdentityDigest, owner.Alias.OwnerRevision, owner.Alias.OwnershipGeneration, owner.EventDigest, nullReplacement(owner.FrozenReplacementID)); e != nil {
			return e
		}
	}
	return verifyReplacementContinuityRows(ctx, ReadTx{handle: tx}, c)
}
func verifyReplacementContinuityRows(ctx context.Context, tx ReadTx, c HostReplacementContinuity) error {
	for _, event := range c.Aliases {
		var raw []byte
		if tx.queryRow(ctx, `SELECT event_bytes FROM host_alias_history WHERE event_ordinal=?`, event.Ordinal).Scan(&raw) != nil || hostaction.BytesDigest(raw) != hostaction.Digest(event) {
			return replacementError(generated.ErrorCodeIntegrityFailure)
		}
	}
	for _, event := range c.Events {
		var raw []byte
		if tx.queryRow(ctx, `SELECT event_bytes FROM host_replacement_events WHERE replacement_id=? AND sequence=?`, event.ReplacementID, event.Sequence).Scan(&raw) != nil || hostaction.BytesDigest(raw) != hostaction.Digest(event) {
			return replacementError(generated.ErrorCodeIntegrityFailure)
		}
	}
	for _, owner := range c.Owners {
		var current HostAliasOwner
		var freeze sql.NullString
		current.Alias.Schema = generated.SchemaIDHostReplacementAliasBinding
		current.Alias.SchemaVersion = "1.0.0"
		current.Alias.AliasID = owner.Alias.AliasID
		if tx.queryRow(ctx, `SELECT owner_host_id,owner_identity_digest,owner_revision,ownership_generation,event_digest,frozen_replacement_id FROM host_alias_owners WHERE alias_id=?`, owner.Alias.AliasID).Scan(&current.Alias.OwnerHostID, &current.Alias.OwnerIdentityDigest, &current.Alias.OwnerRevision, &current.Alias.OwnershipGeneration, &current.EventDigest, &freeze) != nil {
			return replacementError(generated.ErrorCodeIntegrityFailure)
		}
		if freeze.Valid {
			current.FrozenReplacementID = freeze.String
		}
		if hostaction.Digest(current) != hostaction.Digest(owner) {
			if e := verifyReplacementSuccessor(ctx, tx, owner, current); e != nil {
				return e
			}
		}
	}
	return nil
}

func (s *Store) FindFrozenControlReplacement(ctx context.Context, formerHostID, newHostID, pointID string) (out HostReplacementDraft, err error) {
	err = s.Read(ctx, func(tx ReadTx) error {
		rows, e := tx.query(ctx, `SELECT d.draft_id FROM host_replacement_drafts d WHERE d.operation='freeze' AND json_extract(d.request_bytes,'$.restorationClass')='control-database' AND json_extract(d.request_bytes,'$.oldHostId')=? AND json_extract(d.request_bytes,'$.newHostId')=? AND json_extract(d.request_bytes,'$.source.pointId')=? AND EXISTS(SELECT 1 FROM host_replacement_events e WHERE e.replacement_id=d.replacement_id AND e.event_type='frozen') AND NOT EXISTS(SELECT 1 FROM host_replacement_events e WHERE e.replacement_id=d.replacement_id AND e.event_type='committed')`, formerHostID, newHostID, pointID)
		if e != nil {
			return e
		}
		ids := []string{}
		for rows.Next() {
			var id string
			if e = rows.Scan(&id); e != nil {
				rows.Close()
				return e
			}
			ids = append(ids, id)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		if len(ids) != 1 {
			return replacementError(generated.ErrorCodePrerequisiteBlocked)
		}
		row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
		for _, id := range []string{formerHostID, newHostID} {
			if _, e = adoptionGrant(ctx, row, id, "host", "read", "host.read", false); e != nil {
				return e
			}
		}
		out, e = readReplacementDraft(row, ids[0])
		return e
	})
	return
}

func verifyReplacementSuccessor(ctx context.Context, tx ReadTx, prior HostAliasOwner, current HostAliasOwner) error {
	if current.Alias.OwnerRevision <= prior.Alias.OwnerRevision {
		return replacementError(generated.ErrorCodeIntegrityFailure)
	}
	rows, e := tx.query(ctx, `SELECT event_bytes,event_digest FROM host_alias_history WHERE alias_id=? AND owner_revision>? ORDER BY owner_revision`, prior.Alias.AliasID, prior.Alias.OwnerRevision)
	if e != nil {
		return e
	}
	previous := prior.EventDigest
	revision := prior.Alias.OwnerRevision
	var last HostAliasEvent
	for rows.Next() {
		var raw []byte
		var digest string
		if rows.Scan(&raw, &digest) != nil || json.Unmarshal(raw, &last) != nil || hostaction.Digest(last) != digest || last.PreviousDigest != previous || last.Alias.OwnerRevision != revision+1 || last.ReplacementID == "" {
			rows.Close()
			return replacementError(generated.ErrorCodeIntegrityFailure)
		}
		previous = digest
		revision++
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	if previous != current.EventDigest || revision != current.Alias.OwnerRevision || hostaction.Digest(last.Alias) != hostaction.Digest(current.Alias) {
		return replacementError(generated.ErrorCodeIntegrityFailure)
	}
	var eventRaw []byte
	var event HostReplacementEvent
	kind := "committed"
	if current.FrozenReplacementID != "" {
		kind = "frozen"
	}
	if tx.queryRow(ctx, `SELECT event_bytes FROM host_replacement_events WHERE replacement_id=? AND event_type=?`, last.ReplacementID, kind).Scan(&eventRaw) != nil || json.Unmarshal(eventRaw, &event) != nil || hostaction.Digest(event.Execution) != hostaction.Digest(last.Execution) {
		return replacementError(generated.ErrorCodeIntegrityFailure)
	}
	return nil
}

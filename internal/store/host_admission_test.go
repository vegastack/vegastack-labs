package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestHostAdmissionRejectsMissingAuthority(t *testing.T) {
	r := NewGateRepository(nil)
	if _, err := r.ResolveHostAdmission(context.Background(), "host-a"); err == nil {
		t.Fatal("missing authority accepted")
	}
}

// Registration is real persisted authority, but never security qualification.
func TestHostAdmissionRegisteredMissingProof(t *testing.T) {
	f, _, req := actionDraftFixture(t)
	r := NewGateRepository(f.s)
	got, err := r.ResolveHostAdmission(f.ctx, req.HostID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Host.HostID != req.HostID || len(got.Blockers) == 0 || len(got.Qualifications) != 0 || len(got.PrerequisiteDigests) != 0 {
		t.Fatal("registration qualified itself", got)
	}
	if err = r.ValidateHostAdmissionBinding(f.ctx, req.HostID, got.BindingDigest, got.Revision); err != nil {
		t.Fatal(err)
	}
	if err = r.ValidateHostAdmissionBinding(f.ctx, req.HostID, "sha256:"+strings.Repeat("a", 64), got.Revision); err == nil {
		t.Fatal("wrong binding accepted")
	}
	if _, err = r.CheckHostAdmission(f.ctx, req.HostID, "arbitrary-bypass", time.Now()); err == nil {
		t.Fatal("unknown purpose accepted")
	}
	if _, err = f.s.conn.ExecContext(f.ctx, `UPDATE effective_authorization_grants SET status='revoked' WHERE capability='host.read'`); err != nil {
		t.Fatal(err)
	}
	if _, err = r.ResolveHostAdmission(f.ctx, req.HostID); err == nil {
		t.Fatal("revoked read scope accepted")
	}
}

func TestHostAdmissionProofComparisonExcludesUnrelatedRevision(t *testing.T) {
	f, _, req := actionDraftFixture(t)
	r := NewGateRepository(f.s)
	before, e := r.ResolveHostAdmission(f.ctx, req.HostID)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.conn.ExecContext(f.ctx, `UPDATE system_meta SET state_revision=state_revision+1 WHERE id=1`); e != nil {
		t.Fatal(e)
	}
	if e = r.ValidateHostAdmissionSnapshot(f.ctx, before); e != nil {
		t.Fatal("unrelated revision invalidated proof", e)
	}
	altered := before
	altered.QualificationDigests = []string{"ignored-nonauthority"}
	if hostAdmissionProofDigest(altered) != hostAdmissionProofDigest(before) {
		t.Fatal("opaque qualification list became authority")
	}
	altered = before
	altered.Blockers = append(append([]string(nil), before.Blockers...), "host-binding-changed")
	if e = r.ValidateHostAdmissionSnapshot(f.ctx, altered); e == nil {
		t.Fatal("different proof snapshot accepted")
	}
}

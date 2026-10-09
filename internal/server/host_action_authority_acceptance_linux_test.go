//go:build linux

package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"golang.org/x/crypto/ssh"
)

// Each case first reaches a real issued envelope through persisted API/plan,
// human Slack approval, run and lease. Only then does the test change one
// authoritative prerequisite before the peer's fresh challenge is answered.
// The ordinary loopback peer/temporary-file handler proves no denied effect.
func TestHostActionAuthorityPersistedChallengeChanges(t *testing.T) {
	cases := []string{"human-execute-revoked", "human-ack-grant-revoked", "automation-execute-revoked", "human-disabled", "automation-disabled", "credential-revoked", "credential-material-changed", "state-advanced", "epoch-advanced", "lease-expired", "lease-released", "plan-expired", "target-key-replaced", "old-discovery-confirmation", "changed-caller-uid", "authorization-as-envelope", "envelope-as-authorization"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			reached := false
			denialCode := generated.ErrorCodeExecutionFailed
			// A changed epoch invalidates the prior audit chain used to persist the old
			// run's failure. An unusable response after transport delivery is uncertain.
			if name == "epoch-advanced" {
				denialCode = generated.ErrorCodeIntegrityFailure
			}
			if name == "envelope-as-authorization" {
				denialCode = generated.ErrorCodeRecoveryRequired
			}
			hostActionAcceptance(t, "challenge-denial", hostActionAcceptanceHooks{DenialCode: denialCode, Challenge: func(t *testing.T, db *sql.DB, clock *time.Time, authority *HostActionAuthority, e generated.HostActionEnvelope, c generated.HostActionChallenge) (generated.HostActionAuthorization, error) {
				reached = true
				policy := hostaction.Policy{HostID: e.Bundle.HostID, HostIdentityDigest: e.Bundle.HostIdentityDigest, CallerUID: uint32(e.Bundle.CallerUID), KeyID: e.KeyID, PublicKey: authority.signer.PublicKey()}
				raw, _ := json.Marshal(e)
				if _, err := hostaction.VerifyEnvelope(raw, policy, time.Now()); err != nil {
					t.Fatalf("not a valid issued envelope before change: %v", err)
				}
				execute := func(q string, args ...any) {
					t.Helper()
					r, err := db.Exec(q, args...)
					if err != nil {
						t.Fatal(err)
					}
					n, err := r.RowsAffected()
					if err != nil || n != 1 {
						t.Fatalf("mutation must affect one persisted prerequisite: %d %v", n, err)
					}
				}
				resign := func() {
					message, err := hostaction.EnvelopeMessage(e.Bundle, e.KeyID)
					if err != nil {
						t.Fatal(err)
					}
					signature, err := authority.signer.Sign(context.Background(), message)
					if err != nil {
						t.Fatal(err)
					}
					e.Signature = base64.StdEncoding.EncodeToString(signature)
					c.BundleDigest, err = hostaction.BundleDigest(e.Bundle)
					if err != nil {
						t.Fatal(err)
					}
				}
				switch name {
				case "human-execute-revoked":
					execute(`UPDATE effective_authorization_grants SET status='revoked' WHERE grant_id='action-execute'`)
				case "human-ack-grant-revoked":
					execute(`UPDATE effective_authorization_grants SET status='revoked' WHERE grant_id='action-acknowledge'`)
				case "automation-execute-revoked":
					execute(`UPDATE effective_authorization_grants SET status='revoked' WHERE grant_id='automation-action'`)
				case "human-disabled":
					execute(`UPDATE effective_authorization_principals SET status='revoked' WHERE principal_id='operator-a'`)
				case "automation-disabled":
					execute(`UPDATE effective_authorization_principals SET status='revoked' WHERE principal_id='automation-a'`)
				case "credential-revoked", "credential-material-changed":
					status, material := "revoked", "version-a"
					if name == "credential-material-changed" {
						// Retire the old material first so this exercises a sole new
						// active version, rather than ambiguous simultaneous versions.
						execute(`INSERT INTO credential_reference_versions SELECT 'challenge-old-revoked',reference_id,consumer_id,purpose_id,target_id,resolver_id,material_version,fingerprint,'revoked',state_revision+1,recovery_epoch,activated_at,verified_consumers_bytes,declaration_id,declaration_revision,plan_id,plan_digest,run_id,step_id,lease_id,human_id,created_at FROM credential_reference_versions WHERE version_id='synthetic-version'`)
						status = "active"
						material = "version-b"
					}
					execute(`INSERT INTO credential_reference_versions SELECT 'challenge-version',reference_id,consumer_id,purpose_id,target_id,resolver_id,?,fingerprint,?,state_revision+1,recovery_epoch,activated_at,verified_consumers_bytes,declaration_id,declaration_revision,plan_id,plan_digest,run_id,step_id,lease_id,human_id,created_at FROM credential_reference_versions WHERE version_id='synthetic-version'`, material, status)
				case "state-advanced":
					execute(`UPDATE system_meta SET state_revision=state_revision+1 WHERE id=1`)
				case "epoch-advanced":
					execute(`UPDATE system_meta SET recovery_epoch=recovery_epoch+1 WHERE id=1`)
				case "lease-expired":
					var expiry string
					if err := db.QueryRow(`SELECT expires_at FROM target_execution_leases WHERE lease_id=?`, e.Bundle.LeaseID).Scan(&expiry); err != nil {
						t.Fatal(err)
					}
					at, err := time.Parse(time.RFC3339, expiry)
					if err != nil {
						t.Fatal(err)
					}
					*clock = at
				case "lease-released":
					execute(`UPDATE target_execution_leases SET status='released',canonical_bytes=CAST(json_set(canonical_bytes,'$.status','released') AS BLOB) WHERE lease_id=?`, e.Bundle.LeaseID)
				case "plan-expired":
					var expiry string
					if err := db.QueryRow(`SELECT expires_at FROM immutable_plans WHERE plan_id=?`, e.Bundle.PlanID).Scan(&expiry); err != nil {
						t.Fatal(err)
					}
					at, err := time.Parse(time.RFC3339, expiry)
					if err != nil {
						t.Fatal(err)
					}
					*clock = at
				case "target-key-replaced":
					var bytes []byte
					if err := db.QueryRow(`SELECT canonical_bytes FROM host_discovery_drafts WHERE draft_id='fixture-target'`).Scan(&bytes); err != nil {
						t.Fatal(err)
					}
					var draft generated.HostDiscoveryTargetDraftRequest
					if err := json.Unmarshal(bytes, &draft); err != nil {
						t.Fatal(err)
					}
					_, private, err := ed25519.GenerateKey(rand.Reader)
					if err != nil {
						t.Fatal(err)
					}
					key, err := ssh.NewSignerFromKey(private)
					if err != nil {
						t.Fatal(err)
					}
					draft.Target.HostKey = string(ssh.MarshalAuthorizedKey(key.PublicKey()))
					draft.Target.Revision++
					draft.ExpectedTargetRevision = 1
					draft.IdempotencyKey = "replaced-target"
					bytes, _ = json.Marshal(draft)
					execute(`INSERT INTO host_discovery_drafts VALUES('challenge-target','candidate-a',2,1,'activate',?,?,'operator-a',0,0)`, hostdiscovery.Digest(draft), bytes)
					execute(`INSERT INTO host_discovery_targets VALUES('candidate-a',2,'challenge-target','active','fixture-plan',0)`)
				case "old-discovery-confirmation":
					e.Bundle.ConsoleConfirmationDigest = hostdiscovery.Digest("old discovery-only console record")
					resign()
				case "changed-caller-uid":
					e.Bundle.CallerUID++
					resign()
				case "authorization-as-envelope":
					valid, err := authority.Authorize(context.Background(), e, c)
					if err != nil {
						t.Fatal(err)
					}
					e.Signature = valid.Signature
				case "envelope-as-authorization":
					valid, err := authority.Authorize(context.Background(), e, c)
					if err != nil {
						t.Fatal(err)
					}
					valid.Signature = e.Signature
					raw, _ := json.Marshal(valid)
					if hostaction.VerifyAuthorization(raw, c, e.Bundle, policy, time.Now()) == nil {
						t.Fatal("envelope signature accepted as fresh authorization")
					}
					return valid, nil
				}
				got, err := authority.Authorize(context.Background(), e, c)
				if err == nil || got.Signature != "" {
					t.Fatalf("changed persisted %s produced authorization: %v", name, err)
				}
				return got, err
			}})
			if !reached {
				t.Fatal("test did not reach issued-envelope challenge boundary")
			}
		})
	}
}
func TestHostActionAuthorityUnchangedAcrossSecond(t *testing.T) {
	reached := false
	hostActionAcceptance(t, "success", hostActionAcceptanceHooks{Challenge: func(t *testing.T, _ *sql.DB, _ *time.Time, authority *HostActionAuthority, e generated.HostActionEnvelope, c generated.HostActionChallenge) (generated.HostActionAuthorization, error) {
		reached = true
		issued, err := time.Parse(time.RFC3339, e.Bundle.IssuedAt)
		if err != nil {
			t.Fatal(err)
		}
		until := time.Until(issued.Add(time.Second))
		if until > 0 {
			time.Sleep(until + 20*time.Millisecond)
		}
		got, err := authority.Authorize(context.Background(), e, c)
		if err != nil {
			t.Fatal(err)
		}
		if got.AuthorizedAt == e.Bundle.IssuedAt {
			t.Fatal("positive roundtrip did not cross timestamp second")
		}
		return got, nil
	}})
	if !reached {
		t.Fatal("challenge was not reached")
	}
}

// These records are immutable after issuance. Attempted rewrites must fail at
// SQLite rather than manufacture a state that no production transition allows.
func TestHostActionAuthorityImmutableApprovalAndLease(t *testing.T) {
	for _, name := range []string{"approval", "lease-shortening"} {
		t.Run(name, func(t *testing.T) {
			reached := false
			hostActionAcceptance(t, "success", hostActionAcceptanceHooks{Challenge: func(t *testing.T, db *sql.DB, _ *time.Time, authority *HostActionAuthority, e generated.HostActionEnvelope, c generated.HostActionChallenge) (generated.HostActionAuthorization, error) {
				reached = true
				var err error
				if name == "approval" {
					_, err = db.Exec(`UPDATE acknowledgement_requests SET status='rejected' WHERE plan_id=?`, e.Bundle.PlanID)
				} else {
					_, err = db.Exec(`UPDATE target_execution_leases SET expires_at=? WHERE lease_id=?`, time.Now().UTC().Format(time.RFC3339), e.Bundle.LeaseID)
				}
				if err == nil {
					t.Fatal("issued authority was mutable")
				}
				return authority.Authorize(context.Background(), e, c)
			}})
			if !reached {
				t.Fatal("no issued envelope")
			}
		})
	}
}

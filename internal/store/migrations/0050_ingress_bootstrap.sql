-- Finite initial ingress effects need provider-assigned nonsecret IDs between
-- separately acknowledged plans. A reserved stage cannot blindly create twice.
CREATE TABLE ingress_bootstrap_receipts (
 profile_id TEXT NOT NULL,
 action TEXT NOT NULL,
 recovery_epoch INTEGER NOT NULL,
 scope_digest TEXT NOT NULL,
 run_id TEXT NOT NULL UNIQUE,
 draft_id TEXT NOT NULL REFERENCES ingress_drafts(draft_id),
 status TEXT NOT NULL CHECK(status IN ('pending','observed','partial')),
 resource_id TEXT NOT NULL,
 result_digest TEXT NOT NULL,
 before_digest TEXT NOT NULL,
 before_dns_content TEXT NOT NULL,
 before_dns_proxied INTEGER NOT NULL,
 PRIMARY KEY(profile_id,action,recovery_epoch)
) STRICT;
CREATE TRIGGER ingress_bootstrap_receipts_no_delete BEFORE DELETE ON ingress_bootstrap_receipts BEGIN SELECT RAISE(ABORT,'Bootstrap receipts retained'); END;
CREATE TRIGGER ingress_bootstrap_receipts_bounded_update BEFORE UPDATE ON ingress_bootstrap_receipts WHEN OLD.status != 'pending' OR NEW.status NOT IN ('observed','partial') OR NEW.profile_id != OLD.profile_id OR NEW.action != OLD.action OR NEW.scope_digest != OLD.scope_digest OR NEW.run_id != OLD.run_id OR NEW.draft_id != OLD.draft_id OR NEW.recovery_epoch != OLD.recovery_epoch OR NEW.before_digest != OLD.before_digest OR NEW.before_dns_content != OLD.before_dns_content OR NEW.before_dns_proxied != OLD.before_dns_proxied BEGIN SELECT RAISE(ABORT,'Bootstrap receipt transition denied'); END;

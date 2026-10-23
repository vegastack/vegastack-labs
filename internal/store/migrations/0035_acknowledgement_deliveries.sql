-- Notification receipts are presentation state, never acknowledgement authority.
CREATE TABLE acknowledgement_deliveries (
    destination TEXT NOT NULL CHECK (length(destination) BETWEEN 1 AND 256),
    message_id TEXT NOT NULL CHECK (length(message_id) BETWEEN 1 AND 256),
    plan_id TEXT NOT NULL REFERENCES immutable_plans(plan_id) ON DELETE RESTRICT,
    plan_digest TEXT NOT NULL CHECK (length(plan_digest) = 71 AND substr(plan_digest, 1, 7) = 'sha256:'),
    review_text TEXT NOT NULL CHECK (length(review_text) <= 32768),
    status TEXT NOT NULL CHECK (status IN ('pending','approved','queued','running','succeeded','rejected','expired','stale','failed','partial','interrupted','cancelled')),
    created_at TEXT NOT NULL,
    completed_at TEXT,
    PRIMARY KEY (destination,message_id),
    CHECK ((status IN ('pending','approved','queued','running','interrupted') AND completed_at IS NULL)
        OR (status IN ('succeeded','rejected','expired','stale','failed','partial','cancelled') AND completed_at IS NOT NULL))
) STRICT;

CREATE TRIGGER acknowledgement_deliveries_binding BEFORE INSERT ON acknowledgement_deliveries
WHEN NOT EXISTS (SELECT 1 FROM immutable_plans p JOIN acknowledgement_requests a ON a.plan_id=p.plan_id
    WHERE p.plan_id=NEW.plan_id AND p.plan_digest=NEW.plan_digest AND a.plan_digest=NEW.plan_digest)
BEGIN SELECT RAISE(ABORT, 'notification plan binding mismatch'); END;

CREATE TRIGGER acknowledgement_deliveries_immutable BEFORE UPDATE ON acknowledgement_deliveries
WHEN NEW.destination != OLD.destination OR NEW.message_id != OLD.message_id
    OR NEW.plan_id != OLD.plan_id OR NEW.plan_digest != OLD.plan_digest
    OR NEW.review_text != OLD.review_text OR NEW.created_at != OLD.created_at
    OR OLD.completed_at IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'notification binding is immutable'); END;

CREATE TRIGGER acknowledgement_deliveries_no_delete BEFORE DELETE ON acknowledgement_deliveries
BEGIN SELECT RAISE(ABORT, 'notification receipt is durable'); END;

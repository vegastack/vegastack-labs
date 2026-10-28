CREATE TABLE notification_readiness_receipts (
 run_id TEXT PRIMARY KEY REFERENCES plan_runs(run_id),
 step_id TEXT NOT NULL,
 lease_id TEXT NOT NULL,
 policy_digest TEXT NOT NULL,
 recovery_epoch INTEGER NOT NULL CHECK(recovery_epoch>=0),
 status TEXT NOT NULL CHECK(status IN ('attempted','completed')),
 receipt_json BLOB NOT NULL CHECK(json_valid(receipt_json)),
 receipt_digest TEXT NOT NULL
);
CREATE TRIGGER notification_readiness_completed_immutable BEFORE UPDATE ON notification_readiness_receipts WHEN OLD.status='completed' BEGIN SELECT RAISE(ABORT,'completed notification receipts are immutable'); END;

-- #225: bounded append-only measurements from actual persisted execution receipts.
-- Observations are audit state, never declaration or gate activation authority.
CREATE TABLE host_control_results (
 run_id TEXT NOT NULL,
 step_id TEXT NOT NULL,
 result_digest TEXT NOT NULL CHECK(length(result_digest)=71),
 ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 7),
 plan_id TEXT NOT NULL,
 plan_digest TEXT NOT NULL CHECK(length(plan_digest)=71),
 sequence_digest TEXT NOT NULL CHECK(length(sequence_digest)=71),
 operation_id TEXT NOT NULL,
 source_host_id TEXT NOT NULL,
 host_id TEXT NOT NULL,
 host_identity_digest TEXT NOT NULL CHECK(length(host_identity_digest)=71),
 recovery_epoch INTEGER NOT NULL CHECK(recovery_epoch>=0),
 receipt_id TEXT NOT NULL,
 receipt_digest TEXT NOT NULL CHECK(length(receipt_digest)=71),
 control_id TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('passed','failed','partial','unsupported','error')),
 observed_at TEXT NOT NULL,
 measurement_digest TEXT NOT NULL CHECK(length(measurement_digest)=71),
 measurement_bytes BLOB NOT NULL CHECK(length(measurement_bytes) BETWEEN 2 AND 16384),
 control_bytes BLOB NOT NULL CHECK(length(control_bytes) BETWEEN 2 AND 16384),
 result_bytes BLOB NOT NULL CHECK(length(result_bytes) BETWEEN 2 AND 262144),
 PRIMARY KEY(run_id,step_id,result_digest,ordinal),
 FOREIGN KEY(receipt_id) REFERENCES execution_receipts(receipt_id)
) STRICT;
CREATE INDEX host_control_results_current ON host_control_results(host_id,recovery_epoch,control_id,observed_at);
CREATE TRIGGER host_control_results_no_update BEFORE UPDATE ON host_control_results BEGIN SELECT RAISE(ABORT,'host control results are append-only'); END;
CREATE TRIGGER host_control_results_no_delete BEFORE DELETE ON host_control_results BEGIN SELECT RAISE(ABORT,'host control results are append-only'); END;

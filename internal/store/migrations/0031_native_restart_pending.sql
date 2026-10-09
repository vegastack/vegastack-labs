-- An unverified self-restart intent stays on its existing run step.
ALTER TABLE plan_run_steps ADD COLUMN native_restart_pending_bytes BLOB
 CHECK(native_restart_pending_bytes IS NULL OR length(native_restart_pending_bytes) BETWEEN 2 AND 262144);
ALTER TABLE plan_run_steps ADD COLUMN native_restart_consumed_run_id TEXT;
ALTER TABLE plan_run_steps ADD COLUMN native_restart_consumed_step_id TEXT
 CHECK((native_restart_consumed_run_id IS NULL AND native_restart_consumed_step_id IS NULL)
 OR (native_restart_pending_bytes IS NOT NULL AND native_restart_consumed_run_id IS NOT NULL AND native_restart_consumed_step_id IS NOT NULL AND length(native_restart_consumed_run_id) BETWEEN 1 AND 128 AND length(native_restart_consumed_step_id) BETWEEN 1 AND 128));

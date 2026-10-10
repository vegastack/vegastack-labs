-- Refresh only a stale same-host registration after verified recovery.
-- Immutable adoption drafts, approvals, plans and audit retain prior history.
DROP TRIGGER managed_hosts_no_update;
CREATE TRIGGER managed_hosts_no_update BEFORE UPDATE ON managed_hosts
WHEN COALESCE((
 NEW.host_id=OLD.host_id AND NEW.target_id=OLD.target_id
 AND NEW.identity_digest=OLD.identity_digest AND NEW.identity_kind=OLD.identity_kind
 AND NEW.identity_class=OLD.identity_class AND NEW.profile_id=OLD.profile_id
 AND NEW.recovery_epoch>OLD.recovery_epoch
 AND NEW.observation_id<>OLD.observation_id AND NEW.draft_id<>OLD.draft_id
 AND EXISTS (
  SELECT 1 FROM system_meta m JOIN recovery_authority_journal j
   ON j.instance_id=m.instance_id AND j.recovery_epoch=m.recovery_epoch AND j.transition='verified'
  WHERE m.id=1 AND m.authority_mode='ready'
   AND NEW.recovery_epoch=m.recovery_epoch AND NEW.state_revision=m.state_revision
 )
 AND EXISTS (
  SELECT 1 FROM host_adoption_drafts d JOIN host_observations o
   ON o.observation_id=NEW.observation_id
   JOIN immutable_plans p ON p.plan_id=NEW.plan_id
   JOIN acknowledgement_requests a ON a.acknowledgement_id=NEW.acknowledgement_id
   JOIN plan_runs r ON r.plan_id=p.plan_id AND r.plan_digest=p.plan_digest AND r.acknowledgement_id=a.acknowledgement_id
   JOIN plan_run_steps s ON s.run_id=r.run_id AND s.target_id=d.draft_id
   JOIN target_execution_leases l ON l.lease_id=s.active_lease_id AND l.run_id=r.run_id AND l.step_id=s.step_id AND l.target_id=s.target_id
  WHERE d.draft_id=NEW.draft_id AND d.recovery_epoch=NEW.recovery_epoch
   AND o.recovery_epoch=NEW.recovery_epoch AND o.target_id=NEW.target_id
   AND p.recovery_epoch=NEW.recovery_epoch AND p.state_revision=NEW.state_revision
   AND a.plan_id=p.plan_id AND a.plan_digest=p.plan_digest
   AND a.recovery_epoch=NEW.recovery_epoch AND a.status='approved' AND a.consumed_at IS NOT NULL
   AND a.human_id=NEW.approving_human_id
   AND r.status='running' AND r.executor_mode='central' AND r.recovery_epoch=NEW.recovery_epoch
   AND s.status='running' AND s.effect_state='intent-recorded'
   AND s.operation_type='host.adopt' AND s.adapter_id='core.host-adoption'
   AND s.input_digest=d.digest AND s.artifact_digest=d.digest
   AND l.status='active' AND l.recovery_epoch=NEW.recovery_epoch
   AND json_extract(p.canonical_bytes,'$.hostAdoption')=CAST(d.canonical_bytes AS TEXT)
   AND json_extract(d.canonical_bytes,'$.hostId')=NEW.host_id
   AND json_extract(d.canonical_bytes,'$.observationId')=NEW.observation_id
   AND json_extract(d.canonical_bytes,'$.confirmation.identityDigest')=NEW.identity_digest
 )
 AND NOT EXISTS (
  SELECT 1 FROM host_replacement_events f WHERE f.event_type='frozen'
   AND f.old_host_id=NEW.host_id
 )
),0)=0
BEGIN SELECT RAISE(ABORT,'registered host recovery binding refused'); END;

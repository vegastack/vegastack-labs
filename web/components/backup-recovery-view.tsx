"use client";

import { FieldHelp } from "@/components/field-help";
import { useEffect, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import type { BrowserRecoveryPoint, BrowserRestoreDraftRequest } from "@/generated/read-api";
import { useReadFailure } from "@/components/query-provider";
import { formatConsoleTime } from "@/components/source-status";
import { ExactPlanLauncher } from "@/components/exact-plan-launcher";
import { ReadPagination } from "@/components/read-pagination";
import { ReadViewState } from "@/components/read-view-state";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/ui/page-header";
import { PropertyList, PropertyLabel, PropertyRow, PropertyValue } from "@/components/ui/property-list";
import { classifyReadFailure } from "@/lib/read-queries";
import { phase5Keys, phase5Queries, useDraftRestore } from "@/lib/phase5-queries";

function backupStatusLabel(value: string): string {
  return ({ healthy: "Backup recorded", failed: "Failed", "recovery-required": "Recovery needed", verified: "Verified", uncertain: "Result uncertain", unknown: "Not checked", planned: "Ready for plan review", pending: "Waiting for verification", active: "Enabled", disabled: "Disabled", succeeded: "Completed", running: "Running", queued: "Waiting to run", blocked: "Blocked" } as Record<string, string>)[value] ?? "Review recorded status";
}

export function BackupRecoveryView() {
  const { failure, clearFailure } = useReadFailure("phase5");
  const queryClient = useQueryClient();
  function recoverReads() {
    // The protected content is unmounted while latched. Discard cleared query
    // snapshots so explicit recovery must obtain fresh prerequisite objects.
    queryClient.removeQueries({ queryKey: phase5Keys.all });
    clearFailure();
  }
  if (failure) return <>
    <PageHeader title="Backups and recovery" description="Recorded backup status and recovery plans." />
    <ReadViewState kind={classifyReadFailure(failure)} title="Backup records cleared" description="Your session, permissions or response integrity changed. Read current authorized records again before preparing any restore." onRetry={recoverReads} />
  </>;
  return <BackupRecoveryContent />;
}

function BackupRecoveryContent() {
  const recoveryPage = useCursorPage();
  const restorePage = useCursorPage();
  const policyPage = useCursorPage();
  const jobPage = useCursorPage();
  const status = useQuery(phase5Queries.backupStatus());
  const audit = useQuery(phase5Queries.auditVerification());
  const recoveryPoints = useQuery(phase5Queries.recoveryPoints({ limit: 25, ...(recoveryPage.cursor ? { cursor: recoveryPage.cursor } : {}) }));
  const restores = useQuery(phase5Queries.restoreStatuses({ limit: 25, ...(restorePage.cursor ? { cursor: restorePage.cursor } : {}) }));
  const policies = useQuery(phase5Queries.scheduledPolicies({ limit: 25, ...(policyPage.cursor ? { cursor: policyPage.cursor } : {}) }));
  const jobs = useQuery(phase5Queries.scheduledJobs({ limit: 25, ...(jobPage.cursor ? { cursor: jobPage.cursor } : {}) }));
  const backup = status.data?.data;
  const auditIncident = audit.data?.data.status === "incident";
  const recoveryStatusKnown = Boolean(backup && audit.data?.data) && status.isSuccess && audit.isSuccess && !status.error && !audit.error;
  const recoveryRequired = backup?.recoveryRequired === true || backup?.status === "recovery-required" || auditIncident;
  return <>
    <PageHeader title="Backups and recovery" description="Review saved backups and restore results. Choose a verified backup to prepare a restore; it will only run after its plan is reviewed and approved." actions={<Button variant="outline" loading={[status, audit, recoveryPoints, restores, policies, jobs].some(query => query.isFetching)} onClick={() => { for (const query of [status, audit, recoveryPoints, restores, policies, jobs]) void query.refetch(); }}>Refresh Backups</Button>} />
    {!recoveryStatusKnown && !status.isPending && !audit.isPending ? <p className="text-sm text-muted-foreground">Restore preparation is unavailable until backup and audit status can be read.</p> : null}
    {recoveryRequired ? <ReadViewState kind="error" title="Recovery required" description={`Changes are disabled until recovery is complete. Keep the current records and follow the recovery procedure: ${backup?.safeNextAction ?? "inspect current recovery state"}.`} /> : null}
    {auditIncident ? <ReadViewState kind="error" title="Audit incident" description="The operation history did not pass verification. Restore preparation and execution remain disabled until that history can be verified." /> : null}
    <section className="space-y-3" aria-labelledby="backup-status-title"><h2 id="backup-status-title" className="text-h3">Backup status</h2>{status.isPending ? <ReadViewState kind="loading" title="Loading backup status" description="Reading the saved backup result." /> : status.error ? <ReadViewState kind={classifyReadFailure(status.error, Boolean(status.data))} title="Backup status unavailable" description="The backup result could not be read. Refresh before choosing a backup." onRetry={() => void status.refetch()} /> : backup ? <Card><CardHeader className="flex flex-row items-center justify-between"><CardTitle>Recorded backup result <FieldHelp label="Backup result">This is the latest saved backup result, not a guarantee that all current data is backed up. Check its reason and the backup date before preparing a restore.</FieldHelp></CardTitle><Badge bordered intent={backup.status === "healthy" && backup.proofClass !== "fixture" ? "success" : backup.status === "failed" || recoveryRequired ? "destructive" : "warning"}>{backup.proofClass === "fixture" ? "Test data" : backupStatusLabel(backup.status)}</Badge></CardHeader><CardContent><PropertyList><PropertyRow><PropertyLabel>Details</PropertyLabel><PropertyValue><details><summary className="cursor-pointer">Technical details</summary>Reason code: {backup.reasonCode}</details></PropertyValue></PropertyRow><PropertyRow><PropertyLabel>Report type</PropertyLabel><PropertyValue>{backup.proofClass === "fixture" ? "Sample data — cannot verify a real backup" : "Recorded backup report"}<details><summary className="cursor-pointer">Technical details</summary>Source: {backup.sourceKind} · Proof class: {backup.proofClass}</details></PropertyValue></PropertyRow><PropertyRow><PropertyLabel>Last usable backup reference</PropertyLabel><PropertyValue>{backup.lastGoodPointId ?? "None"}</PropertyValue></PropertyRow><PropertyRow><PropertyLabel>Next step</PropertyLabel><PropertyValue>{recoveryRequired ? "Follow the recovery procedure before making changes." : "Review the date and verification of the saved backup you want to use."}<details><summary className="cursor-pointer">Technical details</summary><p>Reported status: {backup.status} · Next action: {backup.safeNextAction}</p><p>State revision: {backup.stateRevision} · Recovery epoch: {backup.recoveryEpoch}</p></details></PropertyValue></PropertyRow></PropertyList></CardContent></Card> : null}</section>
    <section className="space-y-3" aria-labelledby="recovery-points-title"><h2 id="recovery-points-title" className="text-h3">Saved backups <FieldHelp label="Saved backups">A recovery point is a saved backup you can restore from. Verified means its recorded verification passed. Check its date and source; restoring may replace current data. Preparing a draft does not start a restore.</FieldHelp></h2><QueryState query={recoveryPoints} emptyTitle="No recovery points" />{recoveryPoints.data ? <><div className="grid gap-3">{recoveryPoints.data.data.items.map((point) => <Card key={point.pointId}><CardHeader className="flex flex-row items-center justify-between"><CardTitle className="font-mono text-base">{point.pointId}</CardTitle><Badge bordered intent={point.verificationStatus === "verified" && point.proofClass !== "fixture" ? "success" : point.verificationStatus === "failed" ? "destructive" : "warning"}>{point.proofClass === "fixture" ? "Test data" : backupStatusLabel(point.verificationStatus)}</Badge></CardHeader><CardContent><PropertyList><PropertyRow><PropertyLabel>Report type</PropertyLabel><PropertyValue>{point.proofClass === "fixture" ? "Sample data — cannot verify a real backup" : "Recorded backup report"}<details><summary className="cursor-pointer">Technical details</summary>Source: {point.sourceKind} · Proof class: {point.proofClass}</details></PropertyValue></PropertyRow><PropertyRow><PropertyLabel>Created</PropertyLabel><PropertyValue>{formatConsoleTime(point.createdAt)}</PropertyValue></PropertyRow><PropertyRow><PropertyLabel>Details</PropertyLabel><PropertyValue><details><summary className="cursor-pointer">Technical details</summary>Reason code: {point.reasonCode}</details></PropertyValue></PropertyRow></PropertyList></CardContent><CardFooter className="justify-end"><RestoreDraftButton point={point} stateRevision={recoveryPoints.data.data.stateRevision} disabled={!recoveryStatusKnown || recoveryRequired || point.proofClass === "fixture" || point.verificationStatus !== "verified"} /></CardFooter></Card>)}</div><ReadPagination label="Recovery points" hasPrevious={recoveryPage.hasPrevious} hasNext={Boolean(recoveryPoints.data.data.nextCursor)} onPrevious={recoveryPage.previous} onNext={() => recoveryPage.next(recoveryPoints.data?.data.nextCursor)} busy={recoveryPoints.isFetching} /></> : null}</section>
    <section className="space-y-3" aria-labelledby="restore-status-title"><h2 id="restore-status-title" className="text-h3">Restore results</h2><QueryState query={restores} emptyTitle="No restore plans" />{restores.data ? <><div className="grid gap-3">{restores.data.data.items.map((restore) => <Card key={restore.planId}><CardHeader className="flex flex-row items-center justify-between"><CardTitle className="font-mono text-base">{restore.planId}</CardTitle><Badge bordered intent={restore.status === "verified" ? "success" : restore.status === "failed" || restore.status === "uncertain" ? "destructive" : "warning"}>{backupStatusLabel(restore.status)}</Badge></CardHeader><CardContent><PropertyList><PropertyRow><PropertyLabel>Recovery point</PropertyLabel><PropertyValue>{restore.pointId}</PropertyValue></PropertyRow><PropertyRow><PropertyLabel>Verification</PropertyLabel><PropertyValue>{backupStatusLabel(restore.verificationStatus)}</PropertyValue></PropertyRow><PropertyRow><PropertyLabel>Details</PropertyLabel><PropertyValue><details><summary className="cursor-pointer">Technical details</summary>Reason code: {restore.reasonCode}</details></PropertyValue></PropertyRow><PropertyRow><PropertyLabel>Next step</PropertyLabel><PropertyValue>{restore.status === "uncertain" ? "Follow the recovery procedure to establish what happened before trying again." : "Review this restore’s plan and recorded result before continuing."}<details><summary className="cursor-pointer">Technical details</summary>Next action: {restore.safeNextAction}</details></PropertyValue></PropertyRow></PropertyList><div className="mt-4"><ExactPlanLauncher kind="restore" planId={restore.planId} destructive disabled={!recoveryStatusKnown || recoveryRequired || restore.status === "uncertain"} /></div></CardContent></Card>)}</div><ReadPagination label="Restore plans" hasPrevious={restorePage.hasPrevious} hasNext={Boolean(restores.data.data.nextCursor)} onPrevious={restorePage.previous} onNext={() => restorePage.next(restores.data?.data.nextCursor)} busy={restores.isFetching} /></> : null}</section>
    <section className="space-y-3" aria-labelledby="scheduled-jobs-title"><h2 id="scheduled-jobs-title" className="text-h3">Scheduled jobs</h2><QueryState query={policies} emptyTitle="No scheduled policies" />{policies.data ? <><div className="grid gap-3 sm:grid-cols-2">{policies.data.data.items.map((policy) => <Card key={policy.policyId}><CardHeader><CardTitle className="font-mono text-base">{policy.policyId}</CardTitle></CardHeader><CardContent><PropertyList><PropertyRow><PropertyLabel>Action</PropertyLabel><PropertyValue>{policy.actionKind === "backup-create" ? "Create a backup" : "Scheduled maintenance"}<details><summary className="cursor-pointer">Technical details</summary>Action: {policy.actionKind}</details></PropertyValue></PropertyRow><PropertyRow><PropertyLabel>Status</PropertyLabel><PropertyValue>{backupStatusLabel(policy.status)}</PropertyValue></PropertyRow><PropertyRow><PropertyLabel>Details</PropertyLabel><PropertyValue><details><summary className="cursor-pointer">Technical details</summary>Reason code: {policy.reasonCode}</details></PropertyValue></PropertyRow></PropertyList></CardContent></Card>)}</div><ReadPagination label="Scheduled policies" hasPrevious={policyPage.hasPrevious} hasNext={Boolean(policies.data.data.nextCursor)} onPrevious={policyPage.previous} onNext={() => policyPage.next(policies.data?.data.nextCursor)} busy={policies.isFetching} /></> : null}<QueryState query={jobs} emptyTitle="No scheduled jobs" />{jobs.data ? <><div className="grid gap-3">{jobs.data.data.items.map((job) => <Card key={job.jobId}><CardHeader className="flex flex-row items-center justify-between"><CardTitle className="font-mono text-base">{job.jobId}</CardTitle><Badge bordered>{backupStatusLabel(job.status)}</Badge></CardHeader><CardContent><p className="text-sm">Schedule: {job.policyId}</p><details><summary className="cursor-pointer">Technical details</summary>Schedule version: {job.policyRevision} · Reason: {job.reasonCode} · Status: {job.status}</details></CardContent></Card>)}</div><ReadPagination label="Scheduled jobs" hasPrevious={jobPage.hasPrevious} hasNext={Boolean(jobs.data.data.nextCursor)} onPrevious={jobPage.previous} onNext={() => jobPage.next(jobs.data?.data.nextCursor)} busy={jobs.isFetching} /></> : null}</section>
  </>;
}

function useCursorPage() {
  const [history, setHistory] = useState<Array<string | undefined>>([undefined]);
  return {
    cursor: history.at(-1),
    hasPrevious: history.length > 1,
    next: (cursor: string | null | undefined) => { if (cursor) setHistory((current) => [...current, cursor]); },
    previous: () => setHistory((current) => current.length > 1 ? current.slice(0, -1) : current),
  };
}

type QueryLike = { isPending: boolean; error: unknown; data?: { data: { items: ReadonlyArray<unknown> } }; refetch: () => unknown };
function QueryState({ query, emptyTitle }: { query: QueryLike; emptyTitle: string }) {
  if (query.isPending) return <ReadViewState kind="loading" title={`Loading ${emptyTitle.replace(/^No /, "").toLowerCase()}`} description="Reading saved records." />;
  if (query.error) return <ReadViewState kind={classifyReadFailure(query.error, Boolean(query.data))} title={`${emptyTitle.replace(/^No /, "")} unavailable`} description="The records could not be read. Refresh to try again." onRetry={() => void query.refetch()} />;
  if (query.data?.data.items.length === 0) return <ReadViewState kind="empty" title={emptyTitle} description="No records are visible to your account." />;
  return null;
}

function RestoreDraftButton({ point, stateRevision, disabled }: { point: BrowserRecoveryPoint; stateRevision: number; disabled: boolean }) {
  const draft = useDraftRestore();
  const button = useRef<HTMLButtonElement>(null);
  useEffect(() => { if (draft.isSuccess || draft.isError) button.current?.focus(); }, [draft.isError, draft.isSuccess]);
  async function createDraft() {
    const request: BrowserRestoreDraftRequest = { schema: "vegastack-labs.dev/browser-restore-draft-request", schemaVersion: "1.0.0", expectedStateRevision: stateRevision, recoveryEpoch: point.recoveryEpoch, targetDigest: point.contentDigest, idempotencyKey: `restore-draft-${crypto.randomUUID()}`, pointId: point.pointId };
    try { await draft.mutateAsync({ pointId: point.pointId, request }); } catch { /* The mutation result below explains the failure. */ }
  }
  return <div className="flex flex-col items-end gap-2"><Button ref={button} variant="outline" disabled={disabled || draft.isPending} loading={draft.isPending} onClick={() => void createDraft()}>Prepare restore</Button><div aria-live="polite" role="status" className="min-h-5 text-sm text-muted-foreground">{draft.data ? `Draft ${draft.data.data.draftId}; change ${draft.data.data.changeId}. Review the restore plan before requesting approval.` : draft.error ? "Draft failed; no restore started." : null}</div></div>;
}

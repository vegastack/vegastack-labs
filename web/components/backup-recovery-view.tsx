"use client";

import { useEffect, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import type { BrowserRecoveryPoint, BrowserRestoreDraftRequest } from "@/generated/read-api";
import { ExactPlanLauncher } from "@/components/exact-plan-launcher";
import { ReadPagination } from "@/components/read-pagination";
import { ReadViewState } from "@/components/read-view-state";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/ui/page-header";
import { PropertyList, PropertyLabel, PropertyRow, PropertyValue } from "@/components/ui/property-list";
import { classifyReadFailure } from "@/lib/read-queries";
import { phase5Queries, useDraftRestore } from "@/lib/phase5-queries";

export function BackupRecoveryView() {
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
  const recoveryRequired = backup?.recoveryRequired === true || backup?.status === "recovery-required" || auditIncident;
  return <>
    <PageHeader title="Backups and recovery" description="Sanitized backup health, recovery points, restore plans, and fixed schedules. Effectful work still uses the exact server plan." />
    {recoveryRequired ? <ReadViewState kind="error" title="Recovery required" description={`${backup?.reasonCode ?? "recovery-required"}. Ordinary mutations are disabled. Preserve current authority and follow the recovery runbook: ${backup?.safeNextAction ?? "inspect current recovery state"}.`} /> : null}
    {auditIncident ? <ReadViewState kind="error" title="Audit incident" description={`${audit.data?.data.reasonCode}. Restore drafts and exact-plan launchers remain disabled until independent continuity is restored.`} /> : null}
    <section className="space-y-3" aria-labelledby="backup-status-title"><h2 id="backup-status-title" className="text-h3">Backup status</h2>{status.isPending ? <ReadViewState kind="loading" title="Loading backup status" description="Reading the sanitized backup projection." /> : status.error ? <ReadViewState kind={classifyReadFailure(status.error, Boolean(status.data))} title="Backup status unavailable" description="No current backup or recovery point can be inferred." onRetry={() => void status.refetch()} /> : backup ? <Card><CardHeader className="flex flex-row items-center justify-between"><CardTitle>Current protection</CardTitle><Badge bordered intent={backup.status === "healthy" ? "success" : backup.status === "failed" || recoveryRequired ? "destructive" : "warning"}>{backup.status}</Badge></CardHeader><CardContent><PropertyList><PropertyRow><PropertyLabel>Reason</PropertyLabel><PropertyValue>{backup.reasonCode}</PropertyValue></PropertyRow><PropertyRow><PropertyLabel>Source class</PropertyLabel><PropertyValue>{backup.sourceKind} · {backup.proofClass}</PropertyValue></PropertyRow><PropertyRow><PropertyLabel>Last-good point</PropertyLabel><PropertyValue>{backup.lastGoodPointId ?? "None"}</PropertyValue></PropertyRow><PropertyRow><PropertyLabel>State binding</PropertyLabel><PropertyValue>revision {backup.stateRevision} · recovery epoch {backup.recoveryEpoch}</PropertyValue></PropertyRow><PropertyRow><PropertyLabel>Safe next action</PropertyLabel><PropertyValue>{backup.safeNextAction}</PropertyValue></PropertyRow></PropertyList></CardContent></Card> : null}</section>
    <section className="space-y-3" aria-labelledby="recovery-points-title"><h2 id="recovery-points-title" className="text-h3">Recovery points</h2><QueryState query={recoveryPoints} emptyTitle="No recovery points" />{recoveryPoints.data ? <><div className="grid gap-3">{recoveryPoints.data.data.items.map((point) => <Card key={point.pointId}><CardHeader className="flex flex-row items-center justify-between"><CardTitle className="font-mono text-base">{point.pointId}</CardTitle><Badge bordered intent={point.verificationStatus === "verified" ? "success" : point.verificationStatus === "failed" ? "destructive" : "warning"}>{point.verificationStatus}</Badge></CardHeader><CardContent><PropertyList><PropertyRow><PropertyLabel>Source class</PropertyLabel><PropertyValue>{point.sourceKind} · {point.proofClass}</PropertyValue></PropertyRow><PropertyRow><PropertyLabel>Created</PropertyLabel><PropertyValue>{point.createdAt}</PropertyValue></PropertyRow><PropertyRow><PropertyLabel>Reason</PropertyLabel><PropertyValue>{point.reasonCode}</PropertyValue></PropertyRow></PropertyList></CardContent><CardFooter className="justify-end"><RestoreDraftButton point={point} stateRevision={recoveryPoints.data.data.stateRevision} disabled={recoveryRequired || point.proofClass === "fixture" || point.verificationStatus !== "verified"} /></CardFooter></Card>)}</div><ReadPagination label="Recovery points" hasPrevious={recoveryPage.hasPrevious} hasNext={Boolean(recoveryPoints.data.data.nextCursor)} onPrevious={recoveryPage.previous} onNext={() => recoveryPage.next(recoveryPoints.data?.data.nextCursor)} busy={recoveryPoints.isFetching} /></> : null}</section>
    <section className="space-y-3" aria-labelledby="restore-status-title"><h2 id="restore-status-title" className="text-h3">Restore status</h2><QueryState query={restores} emptyTitle="No restore plans" />{restores.data ? <><div className="grid gap-3">{restores.data.data.items.map((restore) => <Card key={restore.planId}><CardHeader className="flex flex-row items-center justify-between"><CardTitle className="font-mono text-base">{restore.planId}</CardTitle><Badge bordered intent={restore.status === "verified" ? "success" : restore.status === "failed" || restore.status === "uncertain" ? "destructive" : "warning"}>{restore.status}</Badge></CardHeader><CardContent><PropertyList><PropertyRow><PropertyLabel>Recovery point</PropertyLabel><PropertyValue>{restore.pointId}</PropertyValue></PropertyRow><PropertyRow><PropertyLabel>Verification</PropertyLabel><PropertyValue>{restore.verificationStatus}</PropertyValue></PropertyRow><PropertyRow><PropertyLabel>Reason</PropertyLabel><PropertyValue>{restore.reasonCode}</PropertyValue></PropertyRow><PropertyRow><PropertyLabel>Safe next action</PropertyLabel><PropertyValue>{restore.safeNextAction}</PropertyValue></PropertyRow></PropertyList><div className="mt-4"><ExactPlanLauncher kind="restore" planId={restore.planId} destructive disabled={recoveryRequired || restore.status === "uncertain"} /></div></CardContent></Card>)}</div><ReadPagination label="Restore plans" hasPrevious={restorePage.hasPrevious} hasNext={Boolean(restores.data.data.nextCursor)} onPrevious={restorePage.previous} onNext={() => restorePage.next(restores.data?.data.nextCursor)} busy={restores.isFetching} /></> : null}</section>
    <section className="space-y-3" aria-labelledby="scheduled-jobs-title"><h2 id="scheduled-jobs-title" className="text-h3">Scheduled jobs</h2><QueryState query={policies} emptyTitle="No scheduled policies" />{policies.data ? <><div className="grid gap-3 sm:grid-cols-2">{policies.data.data.items.map((policy) => <Card key={policy.policyId}><CardHeader><CardTitle className="font-mono text-base">{policy.policyId}</CardTitle></CardHeader><CardContent><PropertyList><PropertyRow><PropertyLabel>Action</PropertyLabel><PropertyValue>{policy.actionKind}</PropertyValue></PropertyRow><PropertyRow><PropertyLabel>Status</PropertyLabel><PropertyValue>{policy.status}</PropertyValue></PropertyRow><PropertyRow><PropertyLabel>Reason</PropertyLabel><PropertyValue>{policy.reasonCode}</PropertyValue></PropertyRow></PropertyList></CardContent></Card>)}</div><ReadPagination label="Scheduled policies" hasPrevious={policyPage.hasPrevious} hasNext={Boolean(policies.data.data.nextCursor)} onPrevious={policyPage.previous} onNext={() => policyPage.next(policies.data?.data.nextCursor)} busy={policies.isFetching} /></> : null}<QueryState query={jobs} emptyTitle="No scheduled jobs" />{jobs.data ? <><div className="grid gap-3">{jobs.data.data.items.map((job) => <Card key={job.jobId}><CardHeader className="flex flex-row items-center justify-between"><CardTitle className="font-mono text-base">{job.jobId}</CardTitle><Badge bordered>{job.status}</Badge></CardHeader><CardContent><p className="text-sm">Policy {job.policyId} revision {job.policyRevision} · {job.reasonCode}</p></CardContent></Card>)}</div><ReadPagination label="Scheduled jobs" hasPrevious={jobPage.hasPrevious} hasNext={Boolean(jobs.data.data.nextCursor)} onPrevious={jobPage.previous} onNext={() => jobPage.next(jobs.data?.data.nextCursor)} busy={jobs.isFetching} /></> : null}</section>
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
  if (query.isPending) return <ReadViewState kind="loading" title={`Loading ${emptyTitle.toLowerCase()}`} description="Reading one bounded server page." />;
  if (query.error) return <ReadViewState kind={classifyReadFailure(query.error, Boolean(query.data))} title={`${emptyTitle} unavailable`} description="No empty or healthy state is inferred." onRetry={() => void query.refetch()} />;
  if (query.data?.data.items.length === 0) return <ReadViewState kind="empty" title={emptyTitle} description="No records are visible in this read scope." />;
  return null;
}

function RestoreDraftButton({ point, stateRevision, disabled }: { point: BrowserRecoveryPoint; stateRevision: number; disabled: boolean }) {
  const draft = useDraftRestore();
  const button = useRef<HTMLButtonElement>(null);
  useEffect(() => { if (draft.isSuccess || draft.isError) button.current?.focus(); }, [draft.isError, draft.isSuccess]);
  async function createDraft() {
    const request: BrowserRestoreDraftRequest = { schema: "vegastack-labs.dev/browser-restore-draft-request", schemaVersion: "1.0.0", expectedStateRevision: stateRevision, recoveryEpoch: point.recoveryEpoch, targetDigest: point.contentDigest, idempotencyKey: `restore-draft-${crypto.randomUUID()}`, pointId: point.pointId };
    await draft.mutateAsync({ pointId: point.pointId, request });
  }
  return <div className="flex flex-col items-end gap-2"><Button ref={button} variant="outline" disabled={disabled || draft.isPending} loading={draft.isPending} onClick={() => void createDraft()}>Create inert restore draft</Button><div aria-live="polite" role="status" className="min-h-5 text-sm text-muted-foreground">{draft.data ? `Draft ${draft.data.data.draftId}; change ${draft.data.data.changeId}. Continue through the plan flow.` : draft.error ? "Draft failed; no restore started." : null}</div></div>;
}

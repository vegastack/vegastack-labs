"use client";

import { useEffect, useRef, useState } from "react";
import { RefreshCw, Send } from "lucide-react";
import type { Plan, RunPresentation } from "@/generated/read-api";
import { ApprovalStatus } from "@/components/approval-status";
import { RunRecoveryDialog } from "@/components/run-recovery-dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { planFromView, useApprovalStatus, useExecutePlan, useRequestApproval, type PlanView } from "@/lib/change-queries";

const planStatusLabels = { approved: "Approved", "awaiting-acknowledgement": "Awaiting acknowledgement", cancelled: "Cancelled", expired: "Expired", planned: "Planned" } as const;

export function PlanReview({ view, observeApprovalInitially, onApprovalRequested, onRunStarted }: { view: PlanView; observeApprovalInitially: boolean; onApprovalRequested: () => void; onRunStarted: (run: RunPresentation) => void }) {
  const plan: Plan = planFromView(view);
  const [observeApproval, setObserveApproval] = useState(observeApprovalInitially || plan.status === "approved" || plan.status === "awaiting-acknowledgement");
  const [clock, setClock] = useState(() => Date.now());
  const requestApproval = useRequestApproval();
  const approval = useApprovalStatus(plan.planId, observeApproval);
  const execute = useExecutePlan();
  const approvalButton = useRef<HTMLButtonElement>(null);
  const refreshButton = useRef<HTMLButtonElement>(null);
  const restoreRefreshFocus = useRef(false);

  useEffect(() => { if (requestApproval.isSuccess || requestApproval.isError) approvalButton.current?.focus(); }, [requestApproval.isError, requestApproval.isSuccess]);
  useEffect(() => {
    if (!approval.isFetching && restoreRefreshFocus.current) {
      restoreRefreshFocus.current = false;
      refreshButton.current?.focus();
    }
  }, [approval.isFetching]);
  useEffect(() => {
    const expiresAt = Date.parse(approval.data?.data.expiresAt ?? plan.expiresAt);
    if (!Number.isFinite(expiresAt)) return;
    const timeout = globalThis.setTimeout(() => setClock(Date.now()), Math.max(0, Math.min(expiresAt - Date.now() + 1, 2_147_483_647)));
    return () => globalThis.clearTimeout(timeout);
  }, [approval.data?.data.expiresAt, plan.expiresAt]);

  async function requestSlackApproval() {
    await requestApproval.mutateAsync(plan);
    setObserveApproval(true);
    onApprovalRequested();
  }
  async function startRun() {
    const refreshed = await approval.refetch();
    const current = refreshed.data?.data;
    const unexpired = current ? Date.parse(current.expiresAt) > Date.now() : false;
    if (!current || current.planId !== plan.planId || current.planDigest !== plan.planDigest || current.status !== "approved" || !current.authorizationCurrent || !current.canApply || !unexpired) return;
    const result = await execute.mutateAsync(plan);
    onRunStarted(result.data);
  }

  const status = approval.data?.data;
  const exactApproval = status?.planId === plan.planId && status.planDigest === plan.planDigest ? status : null;
  const authorizationUnexpired = exactApproval ? Date.parse(exactApproval.expiresAt) > clock : false;
  const canApply = exactApproval?.authorizationCurrent === true && exactApproval.canApply === true && exactApproval.status === "approved" && authorizationUnexpired;
  const highRisk = plan.risk !== "routine";
  return <section className="space-y-4" aria-labelledby="plan-review-title" data-plan-status={plan.status}>
    <Card>
      <CardHeader><CardTitle id="plan-review-title">Exact plan review</CardTitle><CardDescription>Planning is inert. Starting this exact digest is a separate, server-authorized action.</CardDescription></CardHeader>
      <CardContent className="space-y-5">
        <div className="flex flex-wrap gap-2"><Badge bordered>{planStatusLabels[plan.status]}</Badge><Badge bordered intent={highRisk ? "warning" : "info"}>{plan.risk}</Badge><Badge bordered>{plan.authorizationBranch} authorization</Badge></div>
        <dl className="grid gap-4 text-sm sm:grid-cols-2">
          <div><dt className="text-muted-foreground">Plan digest</dt><dd className="break-all font-mono text-xs">{plan.planDigest}</dd></div>
          <div><dt className="text-muted-foreground">Readable digest</dt><dd className="break-all font-mono text-xs">{plan.readableDigest}</dd></div>
          <div><dt className="text-muted-foreground">Expires</dt><dd>{plan.expiresAt}</dd></div>
          <div><dt className="text-muted-foreground">Executor</dt><dd>{plan.executorMode}{plan.executorId ? ` — ${plan.executorId}` : ""}</dd></div>
          <div><dt className="text-muted-foreground">Expected interruption</dt><dd>Execution may pause only at server-owned safe boundaries.</dd></div>
          <div><dt className="text-muted-foreground">Verification and recovery</dt><dd>The server records each step&apos;s verification result; inspect the durable run before any recovery action.</dd></div>
        </dl>
        <div>
          <h3 className="text-base font-semibold">Operations and targets</h3>
          <ol className="mt-3 space-y-3">{plan.operations.map(operation => <li className="rounded-md border border-border p-3 text-sm" key={operation.operationId}><span className="font-medium">{operation.sequence}. {operation.operationType}</span><span className="mt-1 block break-all text-muted-foreground">Target {operation.targetId} · Adapter {operation.adapterId}</span></li>)}</ol>
        </div>
		<details open><summary className="min-h-11 cursor-pointer py-3 font-medium">Exact readable plan</summary><pre className="max-h-96 overflow-auto whitespace-pre-wrap rounded-md bg-muted p-4 text-xs" tabIndex={0}>{"readablePlan" in view ? view.readablePlan : "Readable plan unavailable"}</pre></details>
		<details><summary className="min-h-11 cursor-pointer py-3 font-medium">Exact canonical JSON plan</summary><pre className="max-h-96 overflow-auto rounded-md bg-muted p-4 text-xs" tabIndex={0}>{"canonicalPlan" in view ? view.canonicalPlan : JSON.stringify(plan)}</pre></details>
        <div aria-live="polite" className="min-h-6 text-sm" role="status">
          {requestApproval.error ? "Approval request failed. No acknowledgement was created in this browser." : null}
          {approval.error ? " Approval status is unavailable; Start run remains disabled." : null}
          {execute.error ? " Run start failed. Inspect plan authorization before trying a new action." : null}
          {!canApply && exactApproval ? ` ${exactApproval.status === "rejected" ? "Rejected" : exactApproval.status === "expired" ? "Expired" : exactApproval.status === "pending" ? "Pending" : "Stale"} authorization cannot apply.` : null}
        </div>
      </CardContent>
      <CardFooter className="flex-col items-stretch gap-2 sm:flex-row sm:flex-wrap sm:justify-end">
        <Button ref={approvalButton} className="min-h-11" variant="outline" loading={requestApproval.isPending} disabled={requestApproval.isPending || plan.status === "expired" || plan.status === "cancelled"} onClick={() => void requestSlackApproval()}><Send aria-hidden />Request Slack approval</Button>
        {observeApproval ? <Button ref={refreshButton} className="min-h-11" variant="outline" loading={approval.isFetching} onClick={() => { restoreRefreshFocus.current = true; void approval.refetch(); }}><RefreshCw aria-hidden />Refresh approval status</Button> : null}
        <RunRecoveryDialog trigger={<Button className="min-h-11" disabled={!canApply} loading={execute.isPending}>Start run</Button>} title={highRisk ? "Start this high-risk plan?" : "Start this exact plan?"} description={`Only plan ${plan.planId} at digest ${plan.planDigest} will be sent to the server. The browser cannot widen it.`} confirmLabel="Start exact run" pending={execute.isPending} destructive={highRisk} onConfirm={startRun} />
      </CardFooter>
    </Card>
    {exactApproval ? <ApprovalStatus approval={exactApproval} /> : null}
  </section>;
}

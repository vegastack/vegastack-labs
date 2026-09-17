"use client";

import { useEffect, useRef, useState } from "react";
import { RefreshCw, Send } from "lucide-react";
import { ReadClientError, type Plan, type RunPresentation } from "@/generated/read-api";
import { ApprovalStatus } from "@/components/approval-status";
import { RunRecoveryDialog } from "@/components/run-recovery-dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { CodeBlock } from "@/components/ui/code-block";
import { Item, ItemContent, ItemDescription, ItemTitle } from "@/components/ui/item";
import { PropertyList, PropertyLabel, PropertyRow, PropertyValue } from "@/components/ui/property-list";
import { newRunIdempotencyKey, planFromView, useApprovalStatus, useExecutePlan, useRequestApproval, useResolveRun, type PlanView } from "@/lib/change-queries";

const planStatusLabels = { approved: "Approved", "awaiting-acknowledgement": "Awaiting acknowledgement", cancelled: "Cancelled", expired: "Expired", planned: "Planned" } as const;

export function PlanReview({ view, observeApprovalInitially, executionKey, onApprovalRequested, onExecutionPrepared, onExecutionCleared, onRunStarted }: { view: PlanView; observeApprovalInitially: boolean; executionKey: string | null; onApprovalRequested: () => void; onExecutionPrepared: (key: string) => void; onExecutionCleared: () => void; onRunStarted: (run: RunPresentation) => void }) {
  const plan: Plan = planFromView(view);
  const [observeApproval, setObserveApproval] = useState(observeApprovalInitially || plan.status === "approved" || plan.status === "awaiting-acknowledgement");
  const [clock, setClock] = useState(() => Date.now());
  const requestApproval = useRequestApproval();
  const approval = useApprovalStatus(plan.planId, observeApproval);
  const execute = useExecutePlan();
  const resolveRun = useResolveRun();
  const resolveRunAsync = resolveRun.mutateAsync;
  const resolvedKey = useRef<string | null>(null);
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
  useEffect(() => {
    if (!executionKey || resolvedKey.current === executionKey) return;
    resolvedKey.current = executionKey;
    void resolveRunAsync({ planId: plan.planId, idempotencyKey: executionKey }).then(result => onRunStarted(result.data)).catch(() => undefined);
  }, [executionKey, onRunStarted, plan.planId, resolveRunAsync]);

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
    const idempotencyKey = newRunIdempotencyKey();
    // This mounted action owns the first resolution attempt. A remount starts
    // with an empty ref and resolves the persisted key once after reload.
    resolvedKey.current = idempotencyKey;
    onExecutionPrepared(idempotencyKey);
    try {
      const result = await execute.mutateAsync({ plan, idempotencyKey });
      onRunStarted(result.data);
    } catch (error) {
      if (error instanceof ReadClientError && error.kind === "network") {
        try {
          const result = await resolveRunAsync({ planId: plan.planId, idempotencyKey });
          onRunStarted(result.data);
        } catch {}
        return;
      }
      onExecutionCleared();
    }
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
        <div className="flex flex-wrap gap-2"><Badge bordered>{planStatusLabels[plan.status]}</Badge><Badge bordered intent={highRisk ? "warning" : "info"} className="capitalize">{plan.risk}</Badge><Badge bordered>{plan.authorizationBranch} authorization</Badge></div>
        <PropertyList>
          <PropertyRow><PropertyLabel>Plan ID</PropertyLabel><PropertyValue className="break-all font-mono text-xs">{plan.planId}</PropertyValue></PropertyRow>
          <PropertyRow><PropertyLabel>Plan digest</PropertyLabel><PropertyValue className="break-all font-mono text-xs">{plan.planDigest}</PropertyValue></PropertyRow>
          <PropertyRow><PropertyLabel>Readable digest</PropertyLabel><PropertyValue className="break-all font-mono text-xs">{plan.readableDigest}</PropertyValue></PropertyRow>
          <PropertyRow><PropertyLabel>Expires</PropertyLabel><PropertyValue>{plan.expiresAt}</PropertyValue></PropertyRow>
          <PropertyRow><PropertyLabel>Executor</PropertyLabel><PropertyValue>{plan.executorMode}{plan.executorId ? ` — ${plan.executorId}` : ""}</PropertyValue></PropertyRow>
          <PropertyRow><PropertyLabel>Expected interruption</PropertyLabel><PropertyValue>Execution may pause only at server-owned safe boundaries.</PropertyValue></PropertyRow>
          <PropertyRow><PropertyLabel>Verification and recovery</PropertyLabel><PropertyValue>The server records each step&apos;s verification result; inspect the durable run before any recovery action.</PropertyValue></PropertyRow>
        </PropertyList>
        <section className="flex flex-col gap-3">
          <h3 className="text-h4 text-foreground">Operations and targets</h3>
          <ol className="flex flex-col gap-2">{plan.operations.map(operation => <Item key={operation.operationId} variant="outline" size="sm" render={<li />}><ItemContent><ItemTitle>{operation.sequence}. {operation.operationType}</ItemTitle><ItemDescription className="break-all">Target {operation.targetId} · Adapter {operation.adapterId}</ItemDescription></ItemContent></Item>)}</ol>
        </section>
        <Accordion defaultValue={["readable"]}>
          <AccordionItem value="readable">
            <AccordionTrigger>Exact readable plan</AccordionTrigger>
            <AccordionContent>
              <CodeBlock className="[&_[data-slot=code-block-pre]]:whitespace-pre-wrap [&_[data-slot=code-block-pre]]:break-words" copyValue={"readablePlan" in view ? view.readablePlan : ""}>{"readablePlan" in view ? view.readablePlan : "Readable plan unavailable"}</CodeBlock>
            </AccordionContent>
          </AccordionItem>
          <AccordionItem value="json">
            <AccordionTrigger>Exact canonical JSON plan</AccordionTrigger>
            <AccordionContent>
              <CodeBlock language="json" className="[&_[data-slot=code-block-pre]]:whitespace-pre-wrap [&_[data-slot=code-block-pre]]:break-words" copyValue={"canonicalPlan" in view ? view.canonicalPlan : JSON.stringify(plan)}>{"canonicalPlan" in view ? view.canonicalPlan : JSON.stringify(plan)}</CodeBlock>
            </AccordionContent>
          </AccordionItem>
        </Accordion>
        <div aria-live="polite" className="min-h-6 text-sm" role="status">
          {requestApproval.error ? "Approval request failed. No acknowledgement was created in this browser." : null}
          {approval.error ? " Approval status is unavailable; Start run remains disabled." : null}
          {execute.error && executionKey ? " Run response was lost. The browser is checking the exact durable run and will not submit it again." : execute.error ? " Run start failed. Inspect plan authorization before trying a new action." : null}
          {resolveRun.error ? " Exact run status is not available yet. Reload to inspect this same submission; do not start another run." : null}
          {!canApply && exactApproval ? ` ${exactApproval.status === "rejected" ? "Rejected" : exactApproval.status === "expired" ? "Expired" : exactApproval.status === "pending" ? "Pending" : "Stale"} authorization cannot apply.` : null}
        </div>
      </CardContent>
      <CardFooter className="flex-col items-stretch gap-2 sm:flex-row sm:flex-wrap sm:justify-end">
        <Button ref={approvalButton} variant="outline" loading={requestApproval.isPending} disabled={requestApproval.isPending || plan.status === "expired" || plan.status === "cancelled"} onClick={() => void requestSlackApproval()}><Send aria-hidden />Request Slack approval</Button>
        {observeApproval ? <Button ref={refreshButton} variant="outline" loading={approval.isFetching} onClick={() => { restoreRefreshFocus.current = true; void approval.refetch(); }}><RefreshCw aria-hidden />Refresh approval status</Button> : null}
        <RunRecoveryDialog trigger={<Button disabled={!canApply || executionKey !== null} loading={execute.isPending || resolveRun.isPending}>Start run</Button>} title={highRisk ? "Start this high-risk plan?" : "Start this exact plan?"} description={`Only plan ${plan.planId} at digest ${plan.planDigest} will be sent to the server. The browser cannot widen it.`} confirmLabel="Start exact run" pending={execute.isPending} destructive={highRisk} onConfirm={startRun} />
      </CardFooter>
    </Card>
    {exactApproval ? <ApprovalStatus approval={exactApproval} /> : null}
  </section>;
}

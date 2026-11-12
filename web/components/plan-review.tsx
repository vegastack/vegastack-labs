"use client";

import { formatConsoleTime } from "@/components/source-status";

import { useEffect, useRef, useState } from "react";
import { RefreshCw, Send } from "lucide-react";
import { ReadClientError, type Plan, type RunPresentation } from "@/generated/read-api";
import { FieldHelp } from "@/components/field-help";
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

const planStatusLabels = { approved: "Approved", "awaiting-acknowledgement": "Waiting for approval", cancelled: "Cancelled", expired: "Expired", planned: "Planned" } as const;

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
    try {
      await requestApproval.mutateAsync(plan);
      setObserveApproval(true);
      onApprovalRequested();
    } catch { /* Keep the mutation error visible without creating acknowledgement state. */ }
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
      <CardHeader><CardTitle id="plan-review-title">Review this change</CardTitle><CardDescription>Check what will happen and which machines are affected. Preparing this plan has not changed anything.</CardDescription></CardHeader>
      <CardContent className="space-y-5">
        <div className="flex flex-wrap gap-2"><Badge bordered>{planStatusLabels[plan.status]}</Badge><Badge bordered intent={highRisk ? "warning" : "info"} className="capitalize">{plan.risk}</Badge><Badge bordered>{plan.authorizationBranch === "human" ? "Needs human approval" : "Approved by existing policy"}</Badge></div>
        <details className="rounded-lg border border-border p-3"><summary className="cursor-pointer text-sm font-medium">Technical plan details</summary><PropertyList>
          <PropertyRow><PropertyLabel>Plan ID</PropertyLabel><PropertyValue className="break-all font-mono text-xs">{plan.planId}</PropertyValue></PropertyRow>
          <PropertyRow><PropertyLabel>Plan fingerprint</PropertyLabel><PropertyValue className="break-all font-mono text-xs">{plan.planDigest}</PropertyValue></PropertyRow>
          <PropertyRow><PropertyLabel>Plan text fingerprint</PropertyLabel><PropertyValue className="break-all font-mono text-xs">{plan.readableDigest}</PropertyValue></PropertyRow>
          <PropertyRow><PropertyLabel>Expires</PropertyLabel><PropertyValue>{formatConsoleTime(plan.expiresAt)}</PropertyValue></PropertyRow>
          <PropertyRow><PropertyLabel>Runs through</PropertyLabel><PropertyValue>{plan.executorMode}{plan.executorId ? ` — ${plan.executorId}` : ""}</PropertyValue></PropertyRow>
          <PropertyRow><PropertyLabel>If it pauses</PropertyLabel><PropertyValue>Labs pauses only when the current step can stop safely.</PropertyValue></PropertyRow>
          <PropertyRow><PropertyLabel>Checking the result</PropertyLabel><PropertyValue>Labs saves the result of each step. If something fails, read that result before retrying or undoing it.</PropertyValue></PropertyRow>
        </PropertyList></details>
        <p className="text-sm">Plan expires {formatConsoleTime(plan.expiresAt)}. <FieldHelp label="Plan approval">Approval covers only the actions and machines in this plan. Changing its contents requires a new approval. A fingerprint is a check that identifies those exact contents.</FieldHelp></p>
        <section className="flex flex-col gap-3">
          <h3 className="text-h4 text-foreground">What will change</h3>
          <ol className="flex flex-col gap-2">{plan.operations.map(operation => <Item key={operation.operationId} variant="outline" size="sm" render={<li />}><ItemContent><ItemTitle>{operation.sequence}. {operation.operationType.replace(/[._-]+/g, " ")}</ItemTitle><ItemDescription className="break-all">Machine or service: {operation.targetId}</ItemDescription></ItemContent></Item>)}</ol>
        </section>
        <Accordion defaultValue={["readable"]}>
          <AccordionItem value="readable">
            <AccordionTrigger>Full change instructions</AccordionTrigger>
            <AccordionContent>
              <CodeBlock className="[&_[data-slot=code-block-pre]]:whitespace-pre-wrap [&_[data-slot=code-block-pre]]:break-words" copyValue={"readablePlan" in view ? view.readablePlan : ""}>{"readablePlan" in view ? view.readablePlan : "Readable plan unavailable"}</CodeBlock>
            </AccordionContent>
          </AccordionItem>
          <AccordionItem value="json">
            <AccordionTrigger>Technical plan (JSON)</AccordionTrigger>
            <AccordionContent>
              <CodeBlock language="json" className="[&_[data-slot=code-block-pre]]:whitespace-pre-wrap [&_[data-slot=code-block-pre]]:break-words" copyValue={"canonicalPlan" in view ? view.canonicalPlan : JSON.stringify(plan)}>{"canonicalPlan" in view ? view.canonicalPlan : JSON.stringify(plan)}</CodeBlock>
            </AccordionContent>
          </AccordionItem>
        </Accordion>
        <div aria-live="polite" className="min-h-6 text-sm" role="status">
          {requestApproval.error ? "The Slack request failed. This browser has not approved the change." : null}
          {approval.error ? " Approval could not be checked. Start run stays disabled." : null}
          {execute.error && executionKey ? " The result was not received. Labs is looking up this same change; it will not submit it again." : execute.error ? " The change could not start. Check approval and the error before trying again." : null}
          {resolveRun.error ? " The saved result is not available yet. Refresh this change rather than starting another copy." : null}
          {!canApply && exactApproval ? ` ${exactApproval.status === "rejected" ? "Rejected" : exactApproval.status === "expired" ? "Expired" : exactApproval.status === "pending" ? "Pending" : "Stale"} approval cannot be used.` : null}
        </div>
      </CardContent>
      <CardFooter className="flex-col items-stretch gap-2 sm:flex-row sm:flex-wrap sm:justify-end">
        <Button ref={approvalButton} variant="outline" loading={requestApproval.isPending} disabled={requestApproval.isPending || plan.status === "expired" || plan.status === "cancelled"} onClick={() => void requestSlackApproval()}><Send aria-hidden />Request Slack approval</Button>
        {observeApproval ? <Button ref={refreshButton} variant="outline" loading={approval.isFetching} onClick={() => { restoreRefreshFocus.current = true; void approval.refetch(); }}><RefreshCw aria-hidden />Refresh approval status</Button> : null}
        <RunRecoveryDialog trigger={<Button disabled={!canApply || executionKey !== null} loading={execute.isPending || resolveRun.isPending}>Start run</Button>} title={highRisk ? "Start this high-risk plan?" : "Start this exact plan?"} description={`Start only the actions shown above for plan ${plan.planId}? Labs will check approval again before starting. No extra actions can be added to this plan.`} confirmLabel="Start exact run" pending={execute.isPending} destructive={highRisk} onConfirm={startRun} />
      </CardFooter>
    </Card>
    {exactApproval ? <ApprovalStatus approval={exactApproval} /> : null}
  </section>;
}

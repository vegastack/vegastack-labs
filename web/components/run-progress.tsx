"use client";

import { RefreshCw } from "lucide-react";
import type { RunPresentation } from "@/generated/read-api";
import { ReadViewState } from "@/components/read-view-state";
import { RunRecoveryDialog } from "@/components/run-recovery-dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Item, ItemActions, ItemContent, ItemDescription, ItemTitle } from "@/components/ui/item";
import { PropertyList, PropertyLabel, PropertyRow, PropertyValue } from "@/components/ui/property-list";
import { useCancelRun, useResumeRun, useRun } from "@/lib/run-queries";
import { classifyReadFailure } from "@/lib/read-queries";

const labels = { queued: "Queued", running: "Running", partial: "Partial", failed: "Failed", cancelled: "Cancelled", interrupted: "Interrupted", succeeded: "Succeeded" } as const;
const intents = { queued: "info", running: "info", partial: "warning", failed: "destructive", cancelled: "default", interrupted: "warning", succeeded: "success" } as const;

export function RunProgress({ runId }: { runId: string }) {
  const query = useRun(runId);
  const cancel = useCancelRun();
  const resume = useResumeRun();
  const retained = query.data?.data;
  const kind = query.error ? classifyReadFailure(query.error, true) : null;
  if (kind === "denied" || kind === "error") return <ReadViewState kind={kind} title={kind === "denied" ? "Run access denied" : "Run response rejected"} description="Durable run details were cleared. Inspect the run again through an authorized server connection." onRetry={() => void query.refetch()} />;
  if (!retained) return <ReadViewState kind={query.isPending ? "loading" : "unavailable"} title={query.isPending ? "Restoring durable run" : "Run unavailable"} description="Reading the exact durable run from the control plane; execution is never resubmitted." onRetry={() => void query.refetch()} />;
  const presentation = retained;
  const run = presentation.run;
  const canCancel = ["queued", "running", "interrupted"].includes(run.status) && !run.cancellationRequested;
  const canResume = run.status === "interrupted";
	const recoveryRequired = presentation.nextSafeAction === "recovery required; inspect the durable run" || run.steps.some(step => step.progressState === "unknown");
  async function cancelRun() { await cancel.mutateAsync(presentation); }
  async function resumeRun() { await resume.mutateAsync(presentation); }
  return <section aria-labelledby="run-title" className="space-y-4" data-run-status={run.status}>
    {kind ? <ReadViewState kind="stale" title="Showing last known run state" description="The server connection was lost. The browser inspected the durable run once and never resubmitted execution." onRetry={() => void query.refetch()} /> : null}
    <Card>
      <CardHeader><CardTitle id="run-title">Durable run</CardTitle><CardDescription className="break-all">{run.runId} · plan {run.planId}</CardDescription></CardHeader>
      <CardContent className="space-y-5">
        <div aria-live="polite" role="status" className="flex flex-wrap items-center gap-3"><Badge bordered dot intent={intents[run.status]}>{labels[run.status]}</Badge>{recoveryRequired ? <Badge bordered intent="destructive">Recovery required</Badge> : null}{run.cancellationRequested ? <span className="text-sm">Cancellation requested; waiting for a safe boundary.</span> : null}</div>
        <PropertyList><PropertyRow><PropertyLabel>Verification</PropertyLabel><PropertyValue>{run.verificationStatus}</PropertyValue></PropertyRow><PropertyRow><PropertyLabel>Rollback</PropertyLabel><PropertyValue>{run.rollbackStatus}</PropertyValue></PropertyRow><PropertyRow><PropertyLabel>Last update</PropertyLabel><PropertyValue>{run.updatedAt}</PropertyValue></PropertyRow></PropertyList>
        <section className="flex flex-col gap-3"><h3 className="text-h4 text-foreground">Step progress</h3><ol className="flex flex-col gap-2">{run.steps.map(step => <RunStepRow key={step.stepId} step={step} />)}</ol></section>
        <div className="flex flex-col gap-1 rounded-lg border border-border p-4"><h3 className="text-label text-muted-foreground">Next safe action</h3><p className="text-sm text-foreground">{presentation.nextSafeAction}</p></div>
        <div aria-live="assertive" className="min-h-6 text-sm" role="status">{cancel.error ? "Cancel failed; inspect the durable run before another action." : null}{resume.error ? "Resume failed; inspect current recovery and authorization state." : null}</div>
      </CardContent>
      <CardFooter className="flex-col items-stretch gap-2 sm:flex-row sm:justify-end">
        <Button variant="outline" loading={query.isFetching} onClick={() => void query.refetch()}><RefreshCw aria-hidden />Refresh run</Button>
        <RunRecoveryDialog trigger={<Button variant="outline" tone="destructive" disabled={!canCancel}>Cancel run</Button>} title="Request cancellation?" description="The server will stop only at a safe boundary. Completed effects are not undone by this request." confirmLabel="Request cancel" destructive pending={cancel.isPending} onConfirm={cancelRun} />
        <RunRecoveryDialog trigger={<Button variant="outline" disabled={!canResume}>Resume run</Button>} title="Resume this interrupted run?" description="The server will recheck current authorization, recovery, and exact run state before continuing. It will not create another run." confirmLabel="Resume exact run" pending={resume.isPending} onConfirm={resumeRun} />
      </CardFooter>
    </Card>
  </section>;
}

function RunStepRow({ step }: { step: RunPresentation["run"]["steps"][number] }) {
  return (
    <Item variant="outline" size="sm" render={<li />} data-run-step={step.status}>
      <ItemContent>
        <ItemTitle>{step.sequence}. {step.operationType}</ItemTitle>
        <ItemDescription className="break-all">{step.targetId}</ItemDescription>
      </ItemContent>
      <ItemActions>
        <Badge bordered intent={intents[step.status]}>{labels[step.status]}</Badge>
        <Badge variant="outline">{step.progressState}</Badge>
      </ItemActions>
    </Item>
  );
}

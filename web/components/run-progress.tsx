"use client";

import { RefreshCw } from "lucide-react";
import type { RunPresentation, RunStep } from "@/generated/read-api";
import { ReadViewState } from "@/components/read-view-state";
import { RunRecoveryDialog } from "@/components/run-recovery-dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { useCancelRun, useResumeRun, useRun } from "@/lib/run-queries";
import { classifyReadFailure } from "@/lib/read-queries";

const labels = { queued: "Queued", running: "Running", partial: "Partial", failed: "Failed", cancelled: "Cancelled", interrupted: "Interrupted", succeeded: "Succeeded" } as const;
const intents = { queued: "info", running: "info", partial: "warning", failed: "destructive", cancelled: "default", interrupted: "warning", succeeded: "success" } as const;

export function RunProgress({ initial }: { initial: RunPresentation }) {
  const query = useRun(initial);
  const cancel = useCancelRun();
  const resume = useResumeRun();
  const retained = query.data?.data ?? initial;
  const kind = query.error ? classifyReadFailure(query.error, true) : null;
  if (kind === "denied" || kind === "error") return <ReadViewState kind={kind} title={kind === "denied" ? "Run access denied" : "Run response rejected"} description="Durable run details were cleared. Inspect the run again through an authorized server connection." onRetry={() => void query.refetch()} />;
  const presentation = retained;
  const run = presentation.run;
  const canCancel = ["queued", "running", "interrupted"].includes(run.status) && !run.cancellationRequested;
  const canResume = run.status === "interrupted";
  const recoveryRequired = presentation.nextSafeAction === "recovery required; inspect the durable run" || run.steps.some(step => step.effectState === "effect-unknown");
  async function cancelRun() { await cancel.mutateAsync(presentation); }
  async function resumeRun() { await resume.mutateAsync(presentation); }
  return <section aria-labelledby="run-title" className="space-y-4" data-run-status={run.status}>
    {kind ? <ReadViewState kind="stale" title="Showing last known run state" description="The server connection was lost. The browser inspected the durable run once and never resubmitted execution." onRetry={() => void query.refetch()} /> : null}
    <Card>
      <CardHeader><CardTitle id="run-title">Durable run</CardTitle><CardDescription className="break-all">{run.runId} · plan {run.planId}</CardDescription></CardHeader>
      <CardContent className="space-y-5">
        <div aria-live="polite" role="status" className="flex flex-wrap items-center gap-3"><Badge bordered dot intent={intents[run.status]}>{labels[run.status]}</Badge>{recoveryRequired ? <Badge bordered intent="destructive">Recovery required</Badge> : null}{run.cancellationRequested ? <span className="text-sm">Cancellation requested; waiting for a safe boundary.</span> : null}</div>
        <dl className="grid gap-3 text-sm sm:grid-cols-3"><div><dt className="text-muted-foreground">Verification</dt><dd>{run.verificationStatus}</dd></div><div><dt className="text-muted-foreground">Rollback</dt><dd>{run.rollbackStatus}</dd></div><div><dt className="text-muted-foreground">Last update</dt><dd>{run.updatedAt}</dd></div></dl>
        <div><h3 className="text-base font-semibold">Step progress</h3><ol className="mt-3 space-y-3">{run.steps.map(step => <RunStepRow key={step.stepId} step={step} />)}</ol></div>
        <div className="rounded-md border border-border p-4"><h3 className="font-semibold">Next safe action</h3><p className="mt-1 text-sm text-muted-foreground">{presentation.nextSafeAction}</p></div>
        <div aria-live="assertive" className="min-h-6 text-sm" role="status">{cancel.error ? "Cancel failed; inspect the durable run before another action." : null}{resume.error ? "Resume failed; inspect current recovery and authorization state." : null}</div>
      </CardContent>
      <CardFooter className="flex-col items-stretch gap-2 sm:flex-row sm:justify-end">
        <Button className="min-h-11" variant="outline" loading={query.isFetching} onClick={() => void query.refetch()}><RefreshCw aria-hidden />Refresh run</Button>
        <RunRecoveryDialog trigger={<Button className="min-h-11" variant="destructive-outline" disabled={!canCancel}>Cancel run</Button>} title="Request cancellation?" description="The server will stop only at a safe boundary. Completed effects are not undone by this request." confirmLabel="Request cancel" destructive pending={cancel.isPending} onConfirm={cancelRun} />
        <RunRecoveryDialog trigger={<Button className="min-h-11" variant="outline" disabled={!canResume}>Resume run</Button>} title="Resume this interrupted run?" description="The server will recheck current authorization, recovery, and exact run state before continuing. It will not create another run." confirmLabel="Resume exact run" pending={resume.isPending} onConfirm={resumeRun} />
      </CardFooter>
    </Card>
  </section>;
}

function RunStepRow({ step }: { step: RunStep }) {
  return <li className="grid gap-2 rounded-md border border-border p-3 text-sm sm:grid-cols-[minmax(0,1fr)_auto]" data-run-step={step.status}><div><p className="font-medium">{step.sequence}. {step.operationType}</p><p className="break-all text-muted-foreground">{step.targetId} · {step.adapterId}</p></div><div className="flex flex-wrap items-start gap-2"><Badge bordered intent={intents[step.status]}>{labels[step.status]}</Badge><Badge variant="outline">{step.effectState}</Badge></div></li>;
}

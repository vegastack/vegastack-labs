"use client";

import { formatConsoleTime } from "@/components/source-status";

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
  if (kind === "denied" || kind === "error") return <ReadViewState kind={kind} title={kind === "denied" ? "Run access denied" : "Run response rejected"} description="These results were hidden because access could not be confirmed. Reconnect with an account that can view this change." onRetry={() => void query.refetch()} />;
  if (!retained) return <ReadViewState kind={query.isPending ? "loading" : "unavailable"} title={query.isPending ? "Loading saved results" : "Run unavailable"} description="Loading the saved result from Labs. This does not run the change again." onRetry={() => void query.refetch()} />;
  const presentation = retained;
  const run = presentation.run;
  const canCancel = !kind && ["queued", "running", "interrupted"].includes(run.status) && !run.cancellationRequested;
  const canResume = !kind && run.status === "interrupted";
	const recoveryRequired = presentation.nextSafeAction === "recovery required; inspect the durable run" || run.steps.some(step => step.progressState === "unknown");
  async function cancelRun() { try { await cancel.mutateAsync(presentation); } catch { /* Keep the mutation error visible below. */ } }
  async function resumeRun() { try { await resume.mutateAsync(presentation); } catch { /* Keep the mutation error visible below. */ } }
  return <section aria-labelledby="run-title" className="space-y-4" data-run-status={run.status}>
    {kind ? <ReadViewState kind="stale" title="Showing last known run state" description="The connection was lost. These are the last saved results; the change has not been submitted again." onRetry={() => void query.refetch()} /> : null}
    <Card>
      <CardHeader><CardTitle id="run-title">Change progress</CardTitle><CardDescription className="break-all">{run.runId} · plan {run.planId}</CardDescription></CardHeader>
      <CardContent className="space-y-5">
        <div aria-live="polite" role="status" className="flex flex-wrap items-center gap-3"><Badge bordered dot intent={intents[run.status]}>{labels[run.status]}</Badge>{recoveryRequired ? <Badge bordered intent="destructive">Recovery required</Badge> : null}{run.cancellationRequested ? <span className="text-sm">Cancellation requested; waiting for the current step to finish safely.</span> : null}</div>
        <PropertyList><PropertyRow><PropertyLabel>Result checks</PropertyLabel><PropertyValue>{{ pending: "Waiting for checks", incomplete: "Some checks are unfinished", verified: "Checks passed", failed: "Checks failed" }[run.verificationStatus]}</PropertyValue></PropertyRow><PropertyRow><PropertyLabel>Undo status</PropertyLabel><PropertyValue>{{ "not-requested": "Not requested", required: "Needs attention", "separate-plan": "Requires a separate approved plan" }[run.rollbackStatus]}</PropertyValue></PropertyRow><PropertyRow><PropertyLabel>Last update</PropertyLabel><PropertyValue>{formatConsoleTime(run.updatedAt)}</PropertyValue></PropertyRow></PropertyList>
        <section className="flex flex-col gap-3"><h3 className="text-h4 text-foreground">Step progress</h3><ol className="flex flex-col gap-2">{run.steps.map(step => <RunStepRow key={step.stepId} step={step} />)}</ol></section>
        <div className="flex flex-col gap-1 rounded-lg border border-border p-4"><h3 className="text-label text-muted-foreground">What to do next</h3><p className="text-sm text-foreground">{presentation.nextSafeAction}</p></div>
        <div aria-live="assertive" className="min-h-6 text-sm" role="status">{cancel.error ? "Cancel failed. Refresh the saved result before trying another action." : null}{resume.error ? "Resume failed. Read the reported problem and check that approval is still valid." : null}</div>
      </CardContent>
      <CardFooter className="flex-col items-stretch gap-2 sm:flex-row sm:justify-end">
        <Button variant="outline" loading={query.isFetching} onClick={() => void query.refetch()}><RefreshCw aria-hidden />Refresh run</Button>
        <RunRecoveryDialog trigger={<Button variant="outline" tone="destructive" disabled={!canCancel}>Cancel run</Button>} title="Request cancellation?" description="Labs will stop when the current step can safely pause. Changes already made will stay in place." confirmLabel="Request cancel" destructive pending={cancel.isPending} onConfirm={cancelRun} />
        <RunRecoveryDialog trigger={<Button variant="outline" disabled={!canResume}>Resume run</Button>} title="Resume this interrupted run?" description="Labs will check approval and the saved progress before continuing this change. It will not start a second copy." confirmLabel="Resume exact run" pending={resume.isPending} onConfirm={resumeRun} />
      </CardFooter>
    </Card>
  </section>;
}

function RunStepRow({ step }: { step: RunPresentation["run"]["steps"][number] }) {
  return (
    <Item variant="outline" size="sm" render={<li />} data-run-step={step.status}>
      <ItemContent>
        <ItemTitle>{step.sequence}. {step.operationType.replace(/[._-]+/g, " ")}</ItemTitle>
        <ItemDescription className="break-all">{step.targetId}</ItemDescription>
      </ItemContent>
      <ItemActions>
        <Badge bordered intent={intents[step.status]}>{labels[step.status]}</Badge>
        <Badge variant="outline">{{ "not-started": "Not started", started: "Started", unverified: "Not checked yet", verified: "Result checked", unknown: "Result not known" }[step.progressState]}</Badge>
      </ItemActions>
    </Item>
  );
}

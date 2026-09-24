"use client";

import { useState } from "react";
import { PlanReview } from "@/components/plan-review";
import { ReadViewState } from "@/components/read-view-state";
import { RunProgress } from "@/components/run-progress";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { classifyReadFailure } from "@/lib/read-queries";
import { planFromView, usePlan } from "@/lib/change-queries";

export type ExactPlanKind = "backup" | "backup-verify" | "restore";

const labels: Record<ExactPlanKind, string> = {
  backup: "Backup plan",
  "backup-verify": "Backup verification plan",
  restore: "Restore plan",
};

export function ExactPlanLauncher({ kind, planId, destructive, disabled = false }: { kind: ExactPlanKind; planId: string | null; destructive: boolean; disabled?: boolean }) {
  const planQuery = usePlan(disabled ? null : planId);
  const [approvalRequested, setApprovalRequested] = useState(false);
  const [executionKey, setExecutionKey] = useState<string | null>(null);
  const [runId, setRunId] = useState<string | null>(null);

  if (disabled) {
    return <ReadViewState kind="unavailable" title={`${labels[kind]} disabled`} description="Current recovery or audit state blocks ordinary mutations. Resolve the named prerequisites through the manual runbook before opening a plan." />;
  }
  if (!planId) {
    return <Card><CardHeader><CardTitle>{labels[kind]}</CardTitle><CardDescription>No exact server plan is available for this operation.</CardDescription></CardHeader><CardContent className="text-sm text-muted-foreground">Create the inert draft through its supported workflow, then inspect the resulting exact plan here.</CardContent></Card>;
  }
  if (runId) return <RunProgress runId={runId} />;
  if (planQuery.isPending) return <ReadViewState kind="loading" title={`Loading ${labels[kind].toLowerCase()}`} description={`Reading exact plan ${planId} from the server-owned plan engine.`} />;
  if (planQuery.error) return <ReadViewState kind={classifyReadFailure(planQuery.error)} title={`${labels[kind]} unavailable`} description="The saved plan remains inert until its current server projection can be read safely." onRetry={() => void planQuery.refetch()} />;
  if (!planQuery.data) return null;

  const view = planQuery.data.data;
  const plan = planFromView(view);
  const effectiveDestructive = destructive || plan.risk !== "routine";
  return (
    <div data-plan-kind={kind} data-destructive={effectiveDestructive || undefined}>
      <PlanReview
        view={view}
        observeApprovalInitially={approvalRequested}
        executionKey={executionKey}
        onApprovalRequested={() => setApprovalRequested(true)}
        onExecutionPrepared={setExecutionKey}
        onExecutionCleared={() => setExecutionKey(null)}
        onRunStarted={(run) => {
          setApprovalRequested(false);
          setExecutionKey(null);
          setRunId(run.run.runId);
        }}
      />
    </div>
  );
}

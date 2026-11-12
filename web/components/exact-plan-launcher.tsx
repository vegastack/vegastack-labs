"use client";

import { useState } from "react";
import { PlanReview } from "@/components/plan-review";
import { ReadViewState } from "@/components/read-view-state";
import { RunProgress } from "@/components/run-progress";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { classifyReadFailure } from "@/lib/read-queries";
import { planFromView, usePlan } from "@/lib/change-queries";

export type ExactPlanKind = "backup" | "backup-verify" | "restore" | "host-target" | "host-adoption" | "host-action" | "host-access" | "host-role" | "host-replacement";

const labels: Record<ExactPlanKind, string> = {
  "host-target": "Connection setup plan",
  "host-adoption": "Add node plan",
  "host-action": "Node maintenance plan",
  "host-access": "Node login plan",
  "host-role": "Node setup plan",
  "host-replacement": "Replace node plan",
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
    return <ReadViewState kind="unavailable" title={`${labels[kind]} disabled`} description="Changes are paused because backup or history checks need attention. Read the reported problem before trying to continue." />;
  }
  if (!planId) {
    return <Card><CardHeader><CardTitle>{labels[kind]}</CardTitle><CardDescription>No change plan has been created yet.</CardDescription></CardHeader><CardContent className="text-sm text-muted-foreground">Fill in the form above to prepare a plan. Preparing a plan does not change a machine.</CardContent></Card>;
  }
  if (runId) return <RunProgress runId={runId} />;
  if (planQuery.isPending) return <ReadViewState kind="loading" title={`Loading ${labels[kind].toLowerCase()}`} description={`Reading exact plan ${planId} from the Labs server.`} />;
  if (planQuery.error) return <ReadViewState kind={classifyReadFailure(planQuery.error)} title={`${labels[kind]} unavailable`} description="The plan could not be loaded. Nothing will run until it is loaded, approved and started." onRetry={() => void planQuery.refetch()} />;
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

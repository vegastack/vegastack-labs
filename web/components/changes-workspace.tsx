"use client";

import { useEffect, useState, type FormEvent } from "react";
import { DeclarationEditor } from "@/components/declaration-editor";
import { PlanReview } from "@/components/plan-review";
import { ReadViewState } from "@/components/read-view-state";
import { RunProgress } from "@/components/run-progress";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { FieldLabel, FieldRoot } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { PageHeader } from "@/components/ui/page-header";
import { planFromView, useDeclaration, usePlan } from "@/lib/change-queries";
import { useReadFailure } from "@/components/query-provider";
import { classifyReadFailure } from "@/lib/read-queries";

const handlePattern = /^[a-z][a-z0-9._:-]{0,127}$/;
const historyKey = "vskChangeHandles";
type ChangeHandles = { declarationId?: string; revision?: number; planId?: string; approvalPlanId?: string; executionKey?: string; runId?: string };

function readSafeHandles(value: unknown): ChangeHandles {
  if (!value || typeof value !== "object") return {};
  const candidate = (value as Record<string, unknown>)[historyKey];
  if (!candidate || typeof candidate !== "object") return {};
  const record = candidate as Record<string, unknown>;
  const handles: ChangeHandles = {};
  if (typeof record.declarationId === "string" && handlePattern.test(record.declarationId) && Number.isSafeInteger(record.revision) && Number(record.revision) > 0) {
    handles.declarationId = record.declarationId;
    handles.revision = Number(record.revision);
  }
  if (typeof record.planId === "string" && handlePattern.test(record.planId)) handles.planId = record.planId;
  if (typeof record.approvalPlanId === "string" && record.approvalPlanId === handles.planId) handles.approvalPlanId = record.approvalPlanId;
  if (typeof record.runId === "string" && handlePattern.test(record.runId)) handles.runId = record.runId;
  if (typeof record.executionKey === "string" && handlePattern.test(record.executionKey) && handles.planId && !handles.runId) handles.executionKey = record.executionKey;
  return handles;
}

function replaceSafeHandles(handles: ChangeHandles) {
  const state = globalThis.history.state && typeof globalThis.history.state === "object" ? { ...globalThis.history.state } : {};
  if (Object.keys(handles).length === 0) delete state[historyKey];
  else state[historyKey] = handles;
  globalThis.history.replaceState(state, "");
}

export function ChangesWorkspace() {
  const [reference, setReference] = useState<{ declarationId: string; revision: number } | null>(null);
  const [planId, setPlanId] = useState<string | null>(null);
  const [approvalPlanId, setApprovalPlanId] = useState<string | null>(null);
  const [executionKey, setExecutionKey] = useState<string | null>(null);
  const [runId, setRunId] = useState<string | null>(null);
  const [focusSavedRevision, setFocusSavedRevision] = useState<number | null>(null);
  const [restored, setRestored] = useState(false);
  const declaration = useDeclaration(reference);
  const planQuery = usePlan(planId);
  const { failure: hardFailure, clearFailure } = useReadFailure("changes");

  useEffect(() => {
    const handles = readSafeHandles(globalThis.history.state);
    // Browser history is available only after hydration; this effect restores its safe handles once.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    if (handles.declarationId && handles.revision) setReference({ declarationId: handles.declarationId, revision: handles.revision });
    setPlanId(handles.planId ?? null);
    setApprovalPlanId(handles.approvalPlanId ?? null);
    setExecutionKey(handles.executionKey ?? null);
    setRunId(handles.runId ?? null);
    setRestored(true);
  }, []);

  useEffect(() => {
    if (!restored) return;
    replaceSafeHandles({
      ...(reference ?? {}),
      ...(planId ? { planId } : {}),
      ...(approvalPlanId === planId && approvalPlanId ? { approvalPlanId } : {}),
      ...(executionKey && planId && !runId ? { executionKey } : {}),
      ...(runId ? { runId } : {}),
    });
  }, [approvalPlanId, executionKey, planId, reference, restored, runId]);

  useEffect(() => {
    if (!hardFailure) return;
    // The shared failure boundary is an external session signal; clear every mounted projection together.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setReference(null);
    setPlanId(null);
    setApprovalPlanId(null);
    setExecutionKey(null);
    setRunId(null);
    if (restored) replaceSafeHandles({});
  }, [hardFailure, restored]);

  function openDeclaration(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const declarationId = String(form.get("declarationId") ?? "").trim();
    const revision = Number(form.get("revision"));
    if (!handlePattern.test(declarationId) || !Number.isSafeInteger(revision) || revision < 1) return;
    clearFailure();
    setFocusSavedRevision(null);
    setPlanId(null);
    setApprovalPlanId(null);
    setExecutionKey(null);
    setRunId(null);
    setReference({ declarationId, revision });
  }

  const current = declaration.data?.data;
  const failure = declaration.error ? classifyReadFailure(declaration.error, false) : null;
  const planView = planQuery.data?.data;
  const plan = planView ? planFromView(planView) : null;
  return (
    <>
      <PageHeader
        title="Changes"
        description="Open an exact declaration revision to prepare an inert draft change, plan, approval, and run. Nothing here alters infrastructure until an approved plan executes."
      />
      <div className="space-y-6" data-change-workflow>
      <Card>
        <CardHeader>
          <CardTitle>Open an inert declaration</CardTitle>
          <CardDescription>Enter an exact declaration and revision. Opening or editing it does not change infrastructure.</CardDescription>
        </CardHeader>
        <CardContent>
          <form className="grid gap-4 sm:grid-cols-[minmax(0,1fr)_8rem_auto] sm:items-end" onSubmit={openDeclaration}>
            <FieldRoot>
              <FieldLabel>Declaration ID</FieldLabel>
              <Input name="declarationId" required maxLength={128} pattern="[a-z][a-z0-9._:\\-]{0,127}" autoComplete="off" />
            </FieldRoot>
            <FieldRoot>
              <FieldLabel>Revision</FieldLabel>
              <Input name="revision" type="number" required min={1} step={1} inputMode="numeric" />
            </FieldRoot>
            <Button type="submit">Open declaration</Button>
          </form>
        </CardContent>
      </Card>

      {hardFailure ? <ReadViewState kind="denied" title="Change details cleared" description="Your session, authorization, or response integrity is no longer valid. Reopen an authorized declaration to continue." /> : null}
      {!hardFailure && !reference && !planId && !runId ? <ReadViewState kind="empty" title="No declaration open" description="Open an authorized declaration revision to prepare a draft change." /> : null}
      {declaration.isPending && reference ? <ReadViewState kind="loading" title="Loading declaration" description="Reading the exact authorized revision from the control plane." /> : null}
      {failure ? <ReadViewState kind={failure} title={failure === "denied" ? "Declaration access denied" : failure === "unavailable" ? "Declaration unavailable" : "Declaration response rejected"} description={failure === "denied" ? "Your current session cannot read this declaration." : "No draft, plan, or run action is available until the exact revision can be read safely."} onRetry={() => void declaration.refetch()} /> : null}
      {current ? <DeclarationEditor key={`${current.declarationId}:${current.revision}`} declaration={current} focusAfterSave={focusSavedRevision === current.revision} onSaved={(saved) => { setFocusSavedRevision(saved.revision); setReference({ declarationId: saved.declarationId, revision: saved.revision }); setPlanId(null); setApprovalPlanId(null); setExecutionKey(null); setRunId(null); }} onPlanCreated={(created) => { const createdPlanId = planFromView(created).planId; setPlanId(createdPlanId); setApprovalPlanId(null); setExecutionKey(null); setRunId(null); }} /> : null}
      {planQuery.isPending && planId ? <ReadViewState kind="loading" title="Restoring plan" description="Reading the exact durable plan from the control plane." /> : null}
      {planQuery.error && planId ? <ReadViewState kind={classifyReadFailure(planQuery.error)} title="Plan unavailable" description="The saved plan handle remains inert until the server returns its current authorized projection." onRetry={() => void planQuery.refetch()} /> : null}
      {planView && plan ? <PlanReview key={plan.planId} view={planView} observeApprovalInitially={approvalPlanId === plan.planId} executionKey={executionKey} onApprovalRequested={() => setApprovalPlanId(plan.planId)} onExecutionPrepared={setExecutionKey} onExecutionCleared={() => setExecutionKey(null)} onRunStarted={(started) => { setApprovalPlanId(null); setExecutionKey(null); setRunId(started.run.runId); }} /> : null}
      {runId ? <RunProgress runId={runId} /> : null}
      </div>
    </>
  );
}

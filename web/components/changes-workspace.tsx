"use client";

import { useState, type FormEvent } from "react";
import type { Plan, RunPresentation } from "@/generated/read-api";
import { DeclarationEditor } from "@/components/declaration-editor";
import { PlanReview } from "@/components/plan-review";
import { ReadViewState } from "@/components/read-view-state";
import { RunProgress } from "@/components/run-progress";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useDeclaration } from "@/lib/change-queries";
import { classifyReadFailure } from "@/lib/read-queries";

const fieldClass = "min-h-11 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground outline-none focus-visible:border-ring focus-visible:ring-2 focus-visible:ring-ring/30";

export function ChangesWorkspace() {
  const [reference, setReference] = useState<{ declarationId: string; revision: number } | null>(null);
  const [plan, setPlan] = useState<Plan | null>(null);
  const [run, setRun] = useState<RunPresentation | null>(null);
  const declaration = useDeclaration(reference);

  function openDeclaration(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const declarationId = String(form.get("declarationId") ?? "").trim();
    const revision = Number(form.get("revision"));
    if (!/^[a-z][a-z0-9._:-]{0,127}$/.test(declarationId) || !Number.isSafeInteger(revision) || revision < 1) return;
    setPlan(null);
    setRun(null);
    setReference({ declarationId, revision });
  }

  const current = declaration.data?.data;
  const failure = declaration.error ? classifyReadFailure(declaration.error, false) : null;
  return (
    <div className="space-y-6" data-change-workflow>
      <Card>
        <CardHeader>
          <CardTitle>Open an inert declaration</CardTitle>
          <CardDescription>Enter an exact declaration and revision. Opening or editing it does not change infrastructure.</CardDescription>
        </CardHeader>
        <CardContent>
          <form className="grid gap-4 sm:grid-cols-[minmax(0,1fr)_8rem_auto] sm:items-end" onSubmit={openDeclaration}>
            <label className="grid gap-2 text-sm font-medium">Declaration ID<input className={fieldClass} name="declarationId" required maxLength={128} pattern="[a-z][a-z0-9._:-]{0,127}" autoComplete="off" /></label>
            <label className="grid gap-2 text-sm font-medium">Revision<input className={fieldClass} name="revision" required min={1} step={1} type="number" inputMode="numeric" /></label>
            <Button className="min-h-11" type="submit">Open declaration</Button>
          </form>
        </CardContent>
      </Card>

      {!reference ? <ReadViewState kind="empty" title="No declaration open" description="Open an authorized declaration revision to prepare a draft change." /> : null}
      {declaration.isPending && reference ? <ReadViewState kind="loading" title="Loading declaration" description="Reading the exact authorized revision from the control plane." /> : null}
      {failure ? <ReadViewState kind={failure} title={failure === "denied" ? "Declaration access denied" : failure === "unavailable" ? "Declaration unavailable" : "Declaration response rejected"} description={failure === "denied" ? "Your current session cannot read this declaration." : "No draft, plan, or run action is available until the exact revision can be read safely."} onRetry={() => void declaration.refetch()} /> : null}
      {current ? <DeclarationEditor key={`${current.declarationId}:${current.revision}`} declaration={current} onSaved={(saved) => { setReference({ declarationId: saved.declarationId, revision: saved.revision }); setPlan(null); setRun(null); }} onPlanCreated={(created) => { setPlan(created); setRun(null); }} /> : null}
      {plan ? <PlanReview key={plan.planId} plan={plan} onRunStarted={setRun} /> : null}
      {run ? <RunProgress initial={run} /> : null}
    </div>
  );
}

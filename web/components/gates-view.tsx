"use client";

import { useEffect, useRef, useState, type FormEvent } from "react";
import { useQuery } from "@tanstack/react-query";
import type { GateCheckRequest, GateView } from "@/generated/read-api";
import { GateEvidenceForm } from "@/components/gate-evidence-form";
import { ReadViewState } from "@/components/read-view-state";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { FieldLabel, FieldRoot } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { PageHeader } from "@/components/ui/page-header";
import { PropertyList, PropertyLabel, PropertyRow, PropertyValue } from "@/components/ui/property-list";
import { classifyReadFailure, readQueries } from "@/lib/read-queries";
import { useCheckGate } from "@/lib/phase5-queries";

const outcomeIntent = { passed: "success", blocked: "warning", stale: "warning", unknown: "default", "not-applicable": "default" } as const;
const digestPattern = "sha256:[a-f0-9]{64}";

function GateRecords({ gates, stateRevision, recoveryEpoch }: { gates: ReadonlyArray<GateView>; stateRevision: number; recoveryEpoch: number }) {
  return <div className="grid gap-4" data-gate-records>{gates.map((gate) => <GateRecord key={gate.definition.gateId} gate={gate} stateRevision={stateRevision} recoveryEpoch={recoveryEpoch} />)}</div>;
}

function GateRecord({ gate, stateRevision, recoveryEpoch }: { gate: GateView; stateRevision: number; recoveryEpoch: number }) {
  const [evidenceOpen, setEvidenceOpen] = useState(false);
  const { definition, evaluation, applicabilityReasonCode } = gate;
  const recoveryRequired = evaluation.reasonCode === "recovery-required";
  const cannotDraft = recoveryRequired || !evaluation.readyForInput || evaluation.outcome === "not-applicable" || evaluation.evidenceSource === "fixture";
  return <Card data-gate-outcome={evaluation.outcome} data-recovery-required={recoveryRequired || undefined}>
    <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2"><CardTitle className="font-mono">{definition.gateId}</CardTitle><Badge bordered intent={outcomeIntent[evaluation.outcome]}>{evaluation.outcome}</Badge></CardHeader>
    <CardContent className="space-y-4 text-sm">
      <PropertyList>
        <PropertyRow><PropertyLabel>Applicability</PropertyLabel><PropertyValue>{definition.applicability} · {applicabilityReasonCode}</PropertyValue></PropertyRow>
        <PropertyRow><PropertyLabel>Prerequisites</PropertyLabel><PropertyValue>{definition.prerequisiteGateIds.length ? definition.prerequisiteGateIds.join(", ") : "None"}</PropertyValue></PropertyRow>
        <PropertyRow><PropertyLabel>Reason</PropertyLabel><PropertyValue>{evaluation.reasonCode}</PropertyValue></PropertyRow>
        <PropertyRow><PropertyLabel>Evidence source</PropertyLabel><PropertyValue>{evaluation.evidenceSource}</PropertyValue></PropertyRow>
        <PropertyRow><PropertyLabel>Evidence IDs</PropertyLabel><PropertyValue>{evaluation.evidenceIds.length ? evaluation.evidenceIds.join(", ") : "None"}</PropertyValue></PropertyRow>
        <PropertyRow><PropertyLabel>Freshness</PropertyLabel><PropertyValue>{evaluation.evaluatedAt} · {definition.freshnessSeconds}s window</PropertyValue></PropertyRow>
        <PropertyRow><PropertyLabel>State binding</PropertyLabel><PropertyValue>revision {stateRevision} · recovery epoch {recoveryEpoch}</PropertyValue></PropertyRow>
      </PropertyList>
      {evaluation.evidenceSource === "fixture" ? <ReadViewState kind="partial" title="Fixture-only evidence" description="This fixture cannot qualify a live gate." /> : null}
      {recoveryRequired ? <ReadViewState kind="unavailable" title="Recovery required" description="Ordinary mutations are disabled. Preserve current authority and follow the recovery runbook before checking or drafting evidence." /> : null}
      <GateCheckForm gate={gate} stateRevision={stateRevision} recoveryEpoch={recoveryEpoch} disabled={recoveryRequired} />
      <p className="text-muted-foreground">Safe next action: {cannotDraft ? "Inspect prerequisites and current evidence with the CLI." : "Create an inert evidence draft, then continue through the existing plan flow."}</p>
    </CardContent>
    <CardFooter className="justify-end"><Button variant="outline" disabled={cannotDraft} onClick={() => setEvidenceOpen((open) => !open)}>{evidenceOpen ? "Close evidence draft" : "Draft evidence"}</Button></CardFooter>
    {evidenceOpen ? <CardContent><GateEvidenceForm gate={gate} stateRevision={stateRevision} recoveryEpoch={recoveryEpoch} disabled={cannotDraft} /></CardContent> : null}
  </Card>;
}

function GateCheckForm({ gate, stateRevision, recoveryEpoch, disabled }: { gate: GateView; stateRevision: number; recoveryEpoch: number; disabled: boolean }) {
  const check = useCheckGate();
  const button = useRef<HTMLButtonElement>(null);
  const [subjectId, setSubjectId] = useState(gate.evaluation.subjectId);
  const [targetDigest, setTargetDigest] = useState("");
  useEffect(() => { if (check.isSuccess || check.isError) button.current?.focus(); }, [check.isError, check.isSuccess]);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const request: GateCheckRequest = { schema: "vegastack-labs.dev/gate-check-request", schemaVersion: "1.0.0", expectedStateRevision: stateRevision, recoveryEpoch, targetDigest, idempotencyKey: `gate-check-${crypto.randomUUID()}`, gateId: gate.definition.gateId, subjectId, definitionVersion: gate.definition.definitionVersion };
    await check.mutateAsync({ gateId: gate.definition.gateId, request });
  }
  return <form className="grid gap-3 rounded-lg border border-border p-4 sm:grid-cols-2" onSubmit={(event) => void submit(event)}>
    <FieldRoot><FieldLabel>Exact subject</FieldLabel><Input value={subjectId} onChange={(event) => setSubjectId(event.target.value)} required maxLength={128} autoComplete="off" /></FieldRoot>
    <FieldRoot><FieldLabel>Target digest</FieldLabel><Input value={targetDigest} onChange={(event) => setTargetDigest(event.target.value)} required pattern={digestPattern} maxLength={71} autoComplete="off" spellCheck={false} /></FieldRoot>
    <div aria-live="polite" role="status" className="min-h-6 text-sm text-muted-foreground sm:col-span-2">{check.data ? `Structured check result: ${check.data.data.outcome}. No evidence was changed.` : check.error ? "Check failed; no readiness state was changed." : "A structured check evaluates current applied evidence only."}</div>
    <Button ref={button} type="submit" variant="outline" className="sm:col-start-2" loading={check.isPending} disabled={disabled || check.isPending}>Check current evidence</Button>
  </form>;
}

export function GatesView() {
  const query = useQuery(readQueries.gates());
  let body: React.ReactNode;
  if (query.isPending) body = <ReadViewState kind="loading" title="Loading derived gates" description="Reading generated definitions and server-derived blockers." />;
  else if (query.error) {
    const kind = classifyReadFailure(query.error, Boolean(query.data));
    const copy = kind === "denied" ? ["Gate status access denied", "Your current session cannot read derived gate state."] : kind === "unavailable" ? ["Gate status temporarily unavailable", "The gate read could not be reached; no result can be inferred."] : kind === "stale" ? ["Showing last known gate state", "This read failed temporarily; retained gate state may no longer be current."] : ["Gate status response rejected", "The response could not be used safely; no gate result can be inferred."];
    const retained = kind === "stale" && query.data ? <GateRecords gates={query.data.data.gates} stateRevision={query.data.stateRevision} recoveryEpoch={query.data.recoveryEpoch} /> : undefined;
    body = <ReadViewState kind={kind} title={copy[0]} description={copy[1]} staleData={retained} onRetry={() => void query.refetch()} />;
  } else if (query.data.data.gates.length === 0) body = <ReadViewState kind="empty" title="No gates in this read scope" description="The server returned no gate definitions for this scope. No gate pass can be inferred." />;
  else body = <GateRecords gates={query.data.data.gates} stateRevision={query.data.stateRevision} recoveryEpoch={query.data.recoveryEpoch} />;
  return <><PageHeader title="Gates" description="Exact readiness derived from applied evidence. Checks are read-only and evidence submissions create inert drafts." />{body}</>;
}

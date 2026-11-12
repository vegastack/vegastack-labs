"use client";

import { FieldHelp } from "@/components/field-help";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { useQuery } from "@tanstack/react-query";
import type { GateCheckRequest, GateView } from "@/generated/read-api";
import { formatConsoleTime } from "@/components/source-status";
import { GateEvidenceForm } from "@/components/gate-evidence-form";
import { ReadViewState } from "@/components/read-view-state";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
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
    <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2"><CardTitle className="font-mono">{definition.gateId}</CardTitle><Badge bordered intent={outcomeIntent[evaluation.outcome]}>{{ passed: "Passed", blocked: "Blocked", stale: "Needs a new check", unknown: "Not checked", "not-applicable": "Not required" }[evaluation.outcome]}</Badge></CardHeader>
    <CardContent className="space-y-4 text-sm">
      <p>{evaluation.outcome === "passed" ? "The saved proof meets this check’s current requirements." : evaluation.outcome === "blocked" ? "This check has not passed. Review the checks needed first and the recorded proof before preparing a new report." : evaluation.outcome === "stale" ? "The saved proof is too old or no longer matches the current settings. Collect current results before continuing." : evaluation.outcome === "not-applicable" ? "This check is not required for the current item or is planned for later." : "There is no confirmed result yet. Review the required proof before continuing."}</p>
      <PropertyList>
        <PropertyRow><PropertyLabel>When this check is needed</PropertyLabel><PropertyValue>{definition.applicability === "deferred" ? "Planned for later" : definition.applicability === "always" ? "Always required" : "Depends on the selected item and settings"}</PropertyValue></PropertyRow>
        <PropertyRow><PropertyLabel>Checks needed first</PropertyLabel><PropertyValue>{definition.prerequisiteGateIds.length ? definition.prerequisiteGateIds.join(", ") : "None"}</PropertyValue></PropertyRow>
        <PropertyRow><PropertyLabel>Details</PropertyLabel><PropertyValue><details><summary className="cursor-pointer">Technical details</summary>Reason code: {evaluation.reasonCode}</details></PropertyValue></PropertyRow>
        <PropertyRow><PropertyLabel>Evidence source</PropertyLabel><PropertyValue>{evaluation.evidenceSource === "fixture" ? "Sample data" : evaluation.evidenceSource === "none" ? "No proof recorded" : "Saved proof"}</PropertyValue></PropertyRow>

        <PropertyRow><PropertyLabel>Saved proof inspected / allowed age</PropertyLabel><PropertyValue>{formatConsoleTime(evaluation.evaluatedAt)} · {definition.freshnessSeconds}s window</PropertyValue></PropertyRow>

      </PropertyList>
      <FieldHelp label="Readiness check">A gate is a required readiness check. Passed means its recorded evidence meets the current requirements; blocked means something is missing. Read the reason and the checks needed first before preparing evidence.</FieldHelp>
      <details><summary className="cursor-pointer font-medium">Technical details</summary><p>Evidence source: {evaluation.evidenceSource}</p><p>Applicability reason: {applicabilityReasonCode}</p><p>Evidence IDs: {evaluation.evidenceIds.length ? evaluation.evidenceIds.join(", ") : "None"}</p><p>State revision: {stateRevision} · Recovery epoch: {recoveryEpoch}</p></details>
      {evaluation.evidenceSource === "fixture" ? <ReadViewState kind="partial" title="Fixture-only evidence" description="This fixture cannot qualify a live gate." /> : null}
      {recoveryRequired ? <ReadViewState kind="unavailable" title="Recovery required" description="Ordinary mutations are disabled. Preserve current authority and follow the recovery runbook before checking or drafting evidence." /> : null}
      <details className="rounded-lg border border-border p-3"><summary className="cursor-pointer font-medium">Check results and submit proof</summary><div className="mt-3 space-y-3">
      <GateCheckForm gate={gate} stateRevision={stateRevision} recoveryEpoch={recoveryEpoch} disabled={recoveryRequired} />
      <p className="text-muted-foreground">Safe next action: {cannotDraft ? "Review the checks needed first and use the command line tool to inspect the missing proof." : "Prepare a proof draft, then review and approve its plan before applying it."}</p>
      <Button variant="outline" disabled={cannotDraft} onClick={() => setEvidenceOpen((open) => !open)}>{evidenceOpen ? "Close proof draft" : "Prepare proof"}</Button>
      {evidenceOpen ? <GateEvidenceForm gate={gate} stateRevision={stateRevision} recoveryEpoch={recoveryEpoch} disabled={cannotDraft} /> : null}
      </div></details>
    </CardContent>
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
    try { await check.mutateAsync({ gateId: gate.definition.gateId, request }); } catch { /* The mutation result below explains the failure. */ }
  }
  return <form className="grid gap-3 rounded-lg border border-border p-4 sm:grid-cols-2" onSubmit={(event) => void submit(event)}>
    <FieldRoot><div className="flex items-center gap-2"><FieldLabel>Item being checked</FieldLabel><FieldHelp label="Item being checked">This is the saved subject ID for the machine, service or site being checked. Keep the prefilled value unless the check output gives a different exact subject.</FieldHelp></div><Input value={subjectId} onChange={(event) => setSubjectId(event.target.value)} required maxLength={128} autoComplete="off" /></FieldRoot>
    <FieldRoot><div className="flex items-center gap-2"><FieldLabel>Target fingerprint</FieldLabel><FieldHelp label="Target fingerprint">Copy targetDigest from the command line check output for this item. A digest is a fingerprint, written as sha256: followed by 64 lowercase hexadecimal characters. It identifies the exact target state; do not calculate or invent one by hand.</FieldHelp></div><Input value={targetDigest} onChange={(event) => setTargetDigest(event.target.value)} required pattern={digestPattern} maxLength={71} autoComplete="off" spellCheck={false} /></FieldRoot>
    <div aria-live="polite" role="status" className="min-h-6 text-sm text-muted-foreground sm:col-span-2">{check.data ? `Check result: ${check.data.data.outcome}. No evidence was changed.` : check.error ? "Check failed; no readiness state was changed." : "Checks saved results and may contact connected services to confirm them. It does not change settings or save new proof."}</div>
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
  return <><PageHeader title="Checks" description="See which readiness checks have passed and what is missing. Read the reason and the checks needed first; open the proof controls only when you have results from the check tool." actions={<Button variant="outline" loading={query.isFetching} onClick={() => void query.refetch()}>Refresh Checks</Button>} />{body}</>;
}

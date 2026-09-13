"use client";

import { useEffect, useRef, useState, type ChangeEvent } from "react";
import { FilePlus2, Save } from "lucide-react";
import type { DeclarationOperation, DeclarationRevisionRequest } from "@/generated/read-api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { useCreatePlan, useSaveDeclaration, type BrowserDeclaration, type PlanView } from "@/lib/change-queries";

const fieldClass = "min-h-11 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground outline-none focus-visible:border-ring focus-visible:ring-2 focus-visible:ring-ring/30";
const identifierPattern = "[a-z][a-z0-9._:\\-]{0,127}";
const digestPattern = "sha256:[a-f0-9]{64}";

export function DeclarationEditor({ declaration, onSaved, onPlanCreated }: { declaration: BrowserDeclaration; onSaved: (saved: BrowserDeclaration) => void; onPlanCreated: (plan: PlanView) => void }) {
  const [operations, setOperations] = useState<DeclarationOperation[]>(() => declaration.operations.map(operation => ({ ...operation })));
  const [reasonDigest, setReasonDigest] = useState("");
  const [dirty, setDirty] = useState(false);
  const save = useSaveDeclaration();
  const createPlan = useCreatePlan();
  const saveButton = useRef<HTMLButtonElement>(null);
  const planButton = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (save.isSuccess || save.isError) saveButton.current?.focus();
  }, [save.isError, save.isSuccess]);
  useEffect(() => {
    if (createPlan.isSuccess || createPlan.isError) planButton.current?.focus();
  }, [createPlan.isError, createPlan.isSuccess]);

  function updateOperation(index: number, field: keyof DeclarationOperation, value: string | boolean) {
    setOperations(current => current.map((operation, position) => position === index ? { ...operation, [field]: value } : operation));
    setDirty(true);
  }

  async function saveDeclaration() {
    const request: DeclarationRevisionRequest = {
      schema: "vegastack-labs.dev/declaration-revision-request",
      schemaVersion: "1.0.0",
      declarationId: declaration.declarationId,
      declarationType: declaration.declarationType,
      expectedRevision: declaration.revision + 1,
      expectedStateRevision: declaration.stateRevision,
      recoveryEpoch: declaration.recoveryEpoch,
      operations: operations.map((operation, index) => ({ ...operation, sequence: index + 1 })),
      reasonDigest,
      extensions: declaration.extensions,
    };
    const result = await save.mutateAsync(request);
    setDirty(false);
    onSaved(result.data);
  }

  async function generatePlan() {
    const result = await createPlan.mutateAsync(declaration);
    onPlanCreated(result.data);
  }

  const reasonValid = /^sha256:[a-f0-9]{64}$/.test(reasonDigest);
  return (
    <Card>
      <CardHeader>
        <CardTitle>Draft revision {declaration.revision}</CardTitle>
        <CardDescription>Status: {declaration.status}. Changes stay in this browser until you explicitly save a new inert revision.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-5">
        <dl className="grid gap-3 text-sm sm:grid-cols-3">
          <div><dt className="text-muted-foreground">Declaration</dt><dd className="break-all font-medium">{declaration.declarationId}</dd></div>
          <div><dt className="text-muted-foreground">Type</dt><dd className="break-all font-medium">{declaration.declarationType}</dd></div>
          <div><dt className="text-muted-foreground">Content digest</dt><dd className="break-all font-mono text-xs">{declaration.contentDigest}</dd></div>
        </dl>
        <div className="space-y-4">
          <div className="flex items-center justify-between gap-3"><h2 className="text-lg font-semibold">Operations</h2><span className="text-sm text-muted-foreground">{operations.length} of 256</span></div>
          {operations.map((operation, index) => <OperationFields key={`${operation.operationId}:${index}`} operation={operation} index={index} onChange={updateOperation} onRemove={() => { setOperations(current => current.filter((_, position) => position !== index)); setDirty(true); }} canRemove={operations.length > 1} />)}
          <Button variant="outline" disabled={operations.length >= 256} onClick={() => { setOperations(current => [...current, { sequence: current.length + 1, operationId: "", operationType: "", adapterId: "", targetId: "", inputDigest: "", artifactDigest: "", idempotent: true }]); setDirty(true); }}><FilePlus2 aria-hidden />Add operation</Button>
        </div>
        <label className="grid gap-2 text-sm font-medium">Reason digest<input className={fieldClass} value={reasonDigest} onChange={(event) => { setReasonDigest(event.target.value); setDirty(true); }} required maxLength={71} pattern={digestPattern} spellCheck={false} autoComplete="off" aria-describedby="reason-help" /></label>
        <p id="reason-help" className="text-sm text-muted-foreground">Provide the server-compatible SHA-256 digest of the change reason. Reason text and secrets do not belong in this page.</p>
        <div aria-live="polite" className="min-h-6 text-sm" role="status">
          {dirty ? "Unsaved changes. Generate plan is disabled until this revision is saved." : "Draft matches the last explicit save."}
          {save.error ? " Save failed; no plan or infrastructure change was started." : null}
          {createPlan.error ? " Plan generation failed; the draft remains inert." : null}
        </div>
      </CardContent>
      <CardFooter className="flex-col items-stretch gap-2 sm:flex-row sm:justify-end">
        <Button ref={saveButton} className="min-h-11" loading={save.isPending} disabled={!dirty || !reasonValid || operations.length < 1} onClick={() => void saveDeclaration()}><Save aria-hidden />Save declaration</Button>
        <Button ref={planButton} className="min-h-11" variant="outline" loading={createPlan.isPending} disabled={dirty || save.isPending} onClick={() => void generatePlan()}>Generate plan</Button>
      </CardFooter>
    </Card>
  );
}

function OperationFields({ operation, index, onChange, onRemove, canRemove }: { operation: DeclarationOperation; index: number; onChange: (index: number, field: keyof DeclarationOperation, value: string | boolean) => void; onRemove: () => void; canRemove: boolean }) {
  const fields: Array<{ key: "operationId" | "operationType" | "adapterId" | "targetId" | "inputDigest" | "artifactDigest"; label: string; digest?: boolean }> = [
    { key: "operationId", label: "Operation ID" }, { key: "operationType", label: "Operation type" }, { key: "adapterId", label: "Adapter ID" }, { key: "targetId", label: "Target ID" }, { key: "inputDigest", label: "Input digest", digest: true }, { key: "artifactDigest", label: "Artifact digest", digest: true },
  ];
  return <fieldset className="grid gap-4 rounded-lg border border-border p-4"><legend className="px-1 text-sm font-semibold">Operation {index + 1}</legend><div className="grid gap-4 sm:grid-cols-2">{fields.map(field => <label key={field.key} className="grid gap-2 text-sm font-medium">{field.label}<input className={fieldClass} value={operation[field.key]} onChange={(event: ChangeEvent<HTMLInputElement>) => onChange(index, field.key, event.target.value)} required maxLength={field.digest ? 71 : 128} pattern={field.digest ? digestPattern : identifierPattern} spellCheck={false} autoComplete="off" /></label>)}</div><label className="flex min-h-11 items-center gap-3 text-sm font-medium"><input className="size-5 accent-primary" type="checkbox" checked={operation.idempotent} onChange={(event) => onChange(index, "idempotent", event.target.checked)} />Safe to retry idempotently</label><Button className="justify-self-start" variant="destructive-outline" disabled={!canRemove} onClick={onRemove}>Remove operation</Button></fieldset>;
}

"use client";

import { useEffect, useRef, useState } from "react";
import { FilePlus2, Save } from "lucide-react";
import type { DeclarationOperation, DeclarationRevisionRequest } from "@/generated/read-api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { FieldDescription, FieldLabel, FieldRoot } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { PropertyList, PropertyLabel, PropertyRow, PropertyValue } from "@/components/ui/property-list";
import { useCreatePlan, useSaveDeclaration, type BrowserDeclaration, type PlanView } from "@/lib/change-queries";

const identifierPattern = "[a-z][a-z0-9._:\\-]{0,127}";
const digestPattern = "sha256:[a-f0-9]{64}";

export function DeclarationEditor({ declaration, focusAfterSave, onSaved, onPlanCreated }: { declaration: BrowserDeclaration; focusAfterSave: boolean; onSaved: (saved: BrowserDeclaration) => void; onPlanCreated: (plan: PlanView) => void }) {
  const [operations, setOperations] = useState<DeclarationOperation[]>(() => declaration.operations.map((operation) => ({ ...operation })));
  const [reasonDigest, setReasonDigest] = useState("");
  const [dirty, setDirty] = useState(false);
  const save = useSaveDeclaration();
  const createPlan = useCreatePlan();
  const saveButton = useRef<HTMLButtonElement>(null);
  const planButton = useRef<HTMLButtonElement>(null);
  const reasonInput = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (focusAfterSave) reasonInput.current?.focus();
  }, [focusAfterSave]);

  useEffect(() => {
    if (save.isSuccess || save.isError) saveButton.current?.focus();
  }, [save.isError, save.isSuccess]);
  useEffect(() => {
    if (createPlan.isSuccess || createPlan.isError) planButton.current?.focus();
  }, [createPlan.isError, createPlan.isSuccess]);

  function updateOperation(index: number, field: keyof DeclarationOperation, value: string | boolean) {
    setOperations((current) => current.map((operation, position) => (position === index ? { ...operation, [field]: value } : operation)));
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
      <CardContent className="flex flex-col gap-6">
        <PropertyList>
          <PropertyRow>
            <PropertyLabel>Declaration</PropertyLabel>
            <PropertyValue className="break-all">{declaration.declarationId}</PropertyValue>
          </PropertyRow>
          <PropertyRow>
            <PropertyLabel>Type</PropertyLabel>
            <PropertyValue className="break-all">{declaration.declarationType}</PropertyValue>
          </PropertyRow>
          <PropertyRow>
            <PropertyLabel>Content digest</PropertyLabel>
            <PropertyValue className="break-all font-mono text-xs">{declaration.contentDigest}</PropertyValue>
          </PropertyRow>
        </PropertyList>

        <section className="flex flex-col gap-4">
          <div className="flex items-center justify-between gap-3">
            <h2 className="text-h4 text-foreground">Operations</h2>
            <span className="text-sm text-muted-foreground">{operations.length} of 256</span>
          </div>
          {operations.map((operation, index) => (
            <OperationFields
              key={`${operation.operationId}:${index}`}
              operation={operation}
              index={index}
              onChange={updateOperation}
              onRemove={() => {
                setOperations((current) => current.filter((_, position) => position !== index));
                setDirty(true);
              }}
              canRemove={operations.length > 1}
            />
          ))}
          <Button
            variant="outline"
            className="self-start"
            disabled={operations.length >= 256}
            onClick={() => {
              setOperations((current) => [...current, { sequence: current.length + 1, operationId: "", operationType: "", adapterId: "", targetId: "", inputDigest: "", artifactDigest: "", idempotent: true }]);
              setDirty(true);
            }}
          >
            <FilePlus2 aria-hidden />
            Add operation
          </Button>
        </section>

        <FieldRoot>
          <FieldLabel>Reason digest</FieldLabel>
          <Input
            ref={reasonInput}
            value={reasonDigest}
            onChange={(event) => {
              setReasonDigest(event.target.value);
              setDirty(true);
            }}
            required
            maxLength={71}
            pattern={digestPattern}
            spellCheck={false}
            autoComplete="off"
          />
          <FieldDescription>Provide the server-compatible SHA-256 digest of the change reason. Reason text and secrets do not belong in this page.</FieldDescription>
        </FieldRoot>

        <div aria-live="polite" className="min-h-6 text-sm text-muted-foreground" role="status">
          {dirty ? "Unsaved changes. Generate plan is disabled until this revision is saved." : "Draft matches the last explicit save."}
          {save.error ? " Save failed; no plan or infrastructure change was started." : null}
          {createPlan.error ? " Plan generation failed; the draft remains inert." : null}
        </div>
      </CardContent>
      <CardFooter className="flex-col items-stretch gap-2 sm:flex-row sm:justify-end">
        <Button ref={saveButton} loading={save.isPending} disabled={!dirty || !reasonValid || operations.length < 1} onClick={() => void saveDeclaration()}>
          <Save aria-hidden />
          Save declaration
        </Button>
        <Button ref={planButton} variant="outline" loading={createPlan.isPending} disabled={dirty || save.isPending} onClick={() => void generatePlan()}>
          Generate plan
        </Button>
      </CardFooter>
    </Card>
  );
}

function OperationFields({ operation, index, onChange, onRemove, canRemove }: { operation: DeclarationOperation; index: number; onChange: (index: number, field: keyof DeclarationOperation, value: string | boolean) => void; onRemove: () => void; canRemove: boolean }) {
  const fields: Array<{ key: "operationId" | "operationType" | "adapterId" | "targetId" | "inputDigest" | "artifactDigest"; label: string; digest?: boolean }> = [
    { key: "operationId", label: "Operation ID" },
    { key: "operationType", label: "Operation type" },
    { key: "adapterId", label: "Adapter ID" },
    { key: "targetId", label: "Target ID" },
    { key: "inputDigest", label: "Input digest", digest: true },
    { key: "artifactDigest", label: "Artifact digest", digest: true },
  ];
  const idempotentId = `operation-${index}-idempotent`;
  return (
    <fieldset className="flex flex-col gap-4 rounded-lg border border-border p-4">
      <legend className="px-1 text-label text-muted-foreground">Operation {index + 1}</legend>
      <div className="grid gap-4 sm:grid-cols-2">
        {fields.map((field) => (
          <FieldRoot key={field.key}>
            <FieldLabel>{field.label}</FieldLabel>
            <Input
              value={operation[field.key]}
              onChange={(event) => onChange(index, field.key, event.target.value)}
              required
              maxLength={field.digest ? 71 : 128}
              pattern={field.digest ? digestPattern : identifierPattern}
              spellCheck={false}
              autoComplete="off"
            />
          </FieldRoot>
        ))}
      </div>
      <div className="flex items-center gap-3">
        <Checkbox id={idempotentId} checked={operation.idempotent} onCheckedChange={(checked) => onChange(index, "idempotent", checked === true)} />
        <Label htmlFor={idempotentId}>Safe to retry idempotently</Label>
      </div>
      <Button variant="outline" tone="destructive" className="self-start" disabled={!canRemove} onClick={onRemove}>
        Remove operation
      </Button>
    </fieldset>
  );
}

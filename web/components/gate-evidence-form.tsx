"use client";

import { FieldHelp } from "@/components/field-help";
import { useEffect, useRef, useState, type FormEvent } from "react";
import type { GateEvidenceRequest, GateView } from "@/generated/read-api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { FieldDescription, FieldLabel, FieldRoot } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { PropertyList, PropertyLabel, PropertyRow, PropertyValue } from "@/components/ui/property-list";
import { useDraftGateEvidence } from "@/lib/phase5-queries";

const identifierPattern = "[a-zA-Z0-9][a-zA-Z0-9._:\\-]{0,127}";
const digestPattern = "sha256:[a-f0-9]{64}";

function id(prefix: string) {
  return `${prefix}-${crypto.randomUUID()}`;
}

export function GateEvidenceForm({ gate, stateRevision, recoveryEpoch, disabled = false }: { gate: GateView; stateRevision: number; recoveryEpoch: number; disabled?: boolean }) {
  const draft = useDraftGateEvidence();
  const submitButton = useRef<HTMLButtonElement>(null);
  const [subjectId, setSubjectId] = useState(gate.evaluation.subjectId);
  const [targetDigest, setTargetDigest] = useState("");
  const [artifactDigest, setArtifactDigest] = useState("");
  const [factId, setFactId] = useState("");
  const [valueDigest, setValueDigest] = useState("");
  const [checkId, setCheckId] = useState("");
  const [verifierVersion, setVerifierVersion] = useState("");
  const [result, setResult] = useState<"passed" | "failed" | "unknown">("unknown");
  const [resultDigest, setResultDigest] = useState("");
  const [attachmentDigest, setAttachmentDigest] = useState("");
  const [attachmentSize, setAttachmentSize] = useState("1");
  const [mediaType, setMediaType] = useState("application/octet-stream");
  const [collectorId, setCollectorId] = useState("");
  const [observedAt, setObservedAt] = useState("");

  useEffect(() => {
    if (draft.isSuccess || draft.isError) submitButton.current?.focus();
  }, [draft.isError, draft.isSuccess]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const request: GateEvidenceRequest = {
      schema: "vegastack-labs.dev/gate-evidence-request",
      schemaVersion: "1.1.0",
      expectedStateRevision: stateRevision,
      recoveryEpoch,
      targetDigest,
      idempotencyKey: id("gate-evidence"),
      evidenceId: id("evidence"),
      gateId: gate.definition.gateId,
      subjectId,
      definitionVersion: gate.definition.definitionVersion,
      evaluatorVersion: gate.definition.evaluatorVersion,
      supersedesEvidenceId: null,
      revokesEvidenceId: null,
      artifactDigest,
      observedAt: new Date(observedAt).toISOString(),
      bundle: {
        schema: "vegastack-labs.dev/gate-evidence-bundle",
        schemaVersion: "1.1.0",
        facts: [{ schema: "vegastack-labs.dev/gate-evidence-fact", schemaVersion: "1.1.0", factId, valueDigest }],
        checks: [{ schema: "vegastack-labs.dev/gate-evidence-check", schemaVersion: "1.1.0", checkId, verifierVersion, result, resultDigest }],
        attachments: [{ schema: "vegastack-labs.dev/gate-evidence-attachment", schemaVersion: "1.1.0", digest: attachmentDigest, sizeBytes: Number(attachmentSize), mediaType }],
        collectorId,
        observedAt: new Date(observedAt).toISOString(),
      },
    };
    await draft.mutateAsync({ gateId: gate.definition.gateId, request });
  }

  const submission = draft.data?.data;
  return (
    <Card>
      <CardHeader>
        <CardTitle>Prepare proof for {gate.definition.gateId}</CardTitle>
        <CardDescription>Use the results produced by the check tool for this item. Copy its references and fingerprints below. Preparing a draft does not pass the check; review and approve its plan next.</CardDescription>
      </CardHeader>
      <form onSubmit={(event) => void submit(event)}>
        <CardContent className="grid gap-4 sm:grid-cols-2">
          <p className="text-sm text-muted-foreground sm:col-span-2">Only use actual check results. If you do not have the report, ask the administrator who ran the check; do not fill in example fingerprints.</p>
          <details className="sm:col-span-2"><summary className="cursor-pointer font-medium">Technical details — proof report fields</summary><div className="mt-4 grid gap-4 sm:grid-cols-2">
          <EvidenceField label="Subject ID" value={subjectId} onChange={setSubjectId} pattern={identifierPattern} />
          <EvidenceField label="Target digest" value={targetDigest} onChange={setTargetDigest} pattern={digestPattern} digest />
          <EvidenceField label="Artifact digest" value={artifactDigest} onChange={setArtifactDigest} pattern={digestPattern} digest />
          <EvidenceField label="Fact ID" value={factId} onChange={setFactId} pattern={identifierPattern} />
          <EvidenceField label="Fact value digest" value={valueDigest} onChange={setValueDigest} pattern={digestPattern} digest />
          <EvidenceField label="Check ID" value={checkId} onChange={setCheckId} pattern={identifierPattern} />
          <EvidenceField label="Verifier version" value={verifierVersion} onChange={setVerifierVersion} pattern="[0-9]+\\.[0-9]+\\.[0-9]+" />
          <FieldRoot>
            <div className="flex items-center gap-2"><FieldLabel>Check result</FieldLabel><FieldHelp label="Check result">Copy the outcome from the report. Choose Unknown when it did not establish a pass or failure; never select Passed merely to continue.</FieldHelp></div>
            <select className="h-11 rounded-md border border-input bg-background px-3" value={result} onChange={(event) => setResult(event.target.value as typeof result)}>
              <option value="unknown">Unknown</option><option value="passed">Passed</option><option value="failed">Failed</option>
            </select>
          </FieldRoot>
          <EvidenceField label="Check result digest" value={resultDigest} onChange={setResultDigest} pattern={digestPattern} digest />
          <EvidenceField label="Attachment digest" value={attachmentDigest} onChange={setAttachmentDigest} pattern={digestPattern} digest />
          <EvidenceField label="Attachment size in bytes" value={attachmentSize} onChange={setAttachmentSize} pattern="[1-9][0-9]*" inputMode="numeric" />
          <EvidenceField label="Attachment media type" value={mediaType} onChange={setMediaType} pattern="[a-zA-Z0-9.+-]+/[a-zA-Z0-9.+-]+" />
          <EvidenceField label="Collector ID" value={collectorId} onChange={setCollectorId} pattern={identifierPattern} />
          <FieldRoot>
            <div className="flex items-center gap-2"><FieldLabel>When the check ran</FieldLabel><FieldHelp label="When the check ran">Use the observation time from the check report. The time picker uses your browser’s local timezone and is sent to the server as an exact timestamp.</FieldHelp></div>
            <Input type="datetime-local" value={observedAt} onChange={(event) => setObservedAt(event.target.value)} required />
            <FieldDescription>Enter when the check actually ran, using this browser’s local time. Copy the time from the report; do not use the time you are filling in this form.</FieldDescription>
          </FieldRoot>
          </div></details>
          {submission ? <PropertyList className="sm:col-span-2"><PropertyRow><PropertyLabel>Draft ID</PropertyLabel><PropertyValue className="font-mono">{submission.draftId}</PropertyValue></PropertyRow><PropertyRow><PropertyLabel>Change ID</PropertyLabel><PropertyValue className="font-mono">{submission.changeId}</PropertyValue></PropertyRow></PropertyList> : null}
          <div aria-live="polite" role="status" className="min-h-6 text-sm text-muted-foreground sm:col-span-2">{draft.error ? "Evidence draft failed; no gate state changed." : submission ? "Proof draft created. Review and approve its plan next; this has not passed the check." : "No evidence draft has been submitted."}</div>
        </CardContent>
        <CardFooter className="justify-end"><Button ref={submitButton} type="submit" loading={draft.isPending} disabled={disabled || draft.isPending}>Prepare proof draft</Button></CardFooter>
      </form>
    </Card>
  );
}

const evidenceHelp: Record<string, string> = {
  "Subject ID": "Copy subjectId from the report: the exact machine, service or site checked. The saved subject is prefilled. Example format: host-example.",
  "Target digest": "Copy targetDigest from the report. It fingerprints the exact target state that was checked.",
  "Artifact digest": "Copy artifactDigest from the report. It fingerprints the complete proof artifact produced by the check tool.",
  "Fact ID": "Copy factId from the report’s fact entry. It identifies the measured fact, for example a required baseline check; do not make up a name.",
  "Fact value digest": "Copy valueDigest for that fact from the report. It fingerprints the measured value, rather than the whole report.",
  "Check ID": "Copy checkId from the report’s check entry. It identifies the test that produced this result.",
  "Verifier version": "Copy verifierVersion from the check report, such as 1.0.0. This identifies the version of the tool that checked the proof.",
  "Check result digest": "Copy resultDigest for this check from the report. It fingerprints the recorded check result.",
  "Attachment digest": "Copy digest from the report’s attachment entry. It must match the proof file represented by the attachment.",
  "Attachment size in bytes": "Copy sizeBytes from that attachment entry. Enter a positive whole number of bytes, such as 2048; do not enter KB or MB.",
  "Attachment media type": "Copy mediaType from the attachment entry, such as application/json for a JSON report. Use the actual report value.",
  "Collector ID": "Copy collectorId from the report. It identifies the tool or identity that collected the proof, not the person typing this form.",
};

function EvidenceField({ label, value, onChange, pattern, digest = false, inputMode }: { label: string; value: string; onChange: (value: string) => void; pattern: string; digest?: boolean; inputMode?: "numeric" }) {
  return <FieldRoot><div className="flex items-center gap-2"><FieldLabel>{label}</FieldLabel><FieldHelp label={label}>{evidenceHelp[label]}{digest ? " A SHA-256 fingerprint starts with sha256: and contains 64 lowercase hexadecimal characters after the colon. Copy the complete value; do not invent one." : ""}</FieldHelp></div><Input value={value} onChange={(event) => onChange(event.target.value)} required pattern={pattern} maxLength={digest ? 71 : 128} inputMode={inputMode} autoComplete="off" spellCheck={false} /></FieldRoot>;
}

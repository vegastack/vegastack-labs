"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ReadPagination } from "@/components/read-pagination";
import { ReadViewState } from "@/components/read-view-state";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/ui/page-header";
import { PropertyList, PropertyLabel, PropertyRow, PropertyValue } from "@/components/ui/property-list";
import { classifyReadFailure } from "@/lib/read-queries";
import { phase5Queries } from "@/lib/phase5-queries";

export function AuditView() {
  const [checkpointPages, setCheckpointPages] = useState<Array<string | undefined>>([undefined]);
  const checkpointCursor = checkpointPages.at(-1);
  const checkpoints = useQuery(phase5Queries.auditCheckpoints({ limit: 25, ...(checkpointCursor ? { cursor: checkpointCursor } : {}) }));
  const verification = useQuery(phase5Queries.auditVerification());
  const checkpointFailure = checkpoints.error ? classifyReadFailure(checkpoints.error, Boolean(checkpoints.data)) : null;
  const verificationFailure = verification.error ? classifyReadFailure(verification.error, Boolean(verification.data)) : null;
  const verificationData = verification.data?.data;
  const incident = verificationData?.status === "incident";
  return <>
    <PageHeader title="Audit" description="Sanitized checkpoint continuity and independent verification from the server-owned audit service." />
    {incident ? <ReadViewState kind="error" title="Audit incident" description={`${verificationData.reasonCode}. Preserve current authority and follow the audit continuity runbook. Ordinary mutations remain disabled.`} /> : null}
    <section className="space-y-3" aria-labelledby="audit-verification-title">
      <h2 id="audit-verification-title" className="text-h3">Independent verification</h2>
      {verification.isPending ? <ReadViewState kind="loading" title="Loading audit verification" description="Reading the independent continuity projection." /> : verificationFailure ? <ReadViewState kind={verificationFailure} title="Audit verification unavailable" description="No continuity result can be inferred from this response." onRetry={() => void verification.refetch()} /> : verificationData ? <Card><CardHeader className="flex flex-row items-center justify-between"><CardTitle>Continuity status</CardTitle><Badge bordered intent={incident ? "destructive" : verificationData.status === "anchored" ? "success" : "warning"}>{verificationData.status}</Badge></CardHeader><CardContent><PropertyList><PropertyRow><PropertyLabel>Reason</PropertyLabel><PropertyValue>{verificationData.reasonCode}</PropertyValue></PropertyRow><PropertyRow><PropertyLabel>Source class</PropertyLabel><PropertyValue>{verificationData.sourceKind} · {verificationData.proofClass}</PropertyValue></PropertyRow><PropertyRow><PropertyLabel>Independent match</PropertyLabel><PropertyValue>{verificationData.independentMatch ? "yes" : "no"}</PropertyValue></PropertyRow><PropertyRow><PropertyLabel>Last anchored sequence</PropertyLabel><PropertyValue>{verificationData.lastAnchoredSequence}</PropertyValue></PropertyRow><PropertyRow><PropertyLabel>State binding</PropertyLabel><PropertyValue>revision {verificationData.stateRevision} · recovery epoch {verificationData.recoveryEpoch}</PropertyValue></PropertyRow><PropertyRow><PropertyLabel>Safe next action</PropertyLabel><PropertyValue>{verificationData.safeNextAction}</PropertyValue></PropertyRow></PropertyList></CardContent></Card> : null}
    </section>
    <section className="space-y-3" aria-labelledby="audit-checkpoints-title">
      <h2 id="audit-checkpoints-title" className="text-h3">Audit checkpoints</h2>
      {checkpoints.isPending ? <ReadViewState kind="loading" title="Loading audit checkpoints" description="Reading the first bounded checkpoint page." /> : checkpointFailure ? <ReadViewState kind={checkpointFailure} title="Audit checkpoints unavailable" description="No empty or healthy checkpoint state is inferred." onRetry={() => void checkpoints.refetch()} /> : checkpoints.data?.data.items.length === 0 ? <ReadViewState kind="empty" title="No audit checkpoints" description="No checkpoint is visible in this read scope." /> : <><div className="grid gap-3">{checkpoints.data?.data.items.map((checkpoint) => <Card key={checkpoint.checkpointId}><CardHeader className="flex flex-row items-center justify-between"><CardTitle className="font-mono text-base">{checkpoint.checkpointId}</CardTitle><Badge bordered intent={checkpoint.status === "incident" ? "destructive" : checkpoint.status === "anchored" ? "success" : "warning"}>{checkpoint.status}</Badge></CardHeader><CardContent><PropertyList><PropertyRow><PropertyLabel>Events</PropertyLabel><PropertyValue>{checkpoint.firstEventId}–{checkpoint.lastEventId}</PropertyValue></PropertyRow><PropertyRow><PropertyLabel>Verification</PropertyLabel><PropertyValue>{checkpoint.verificationStatus}</PropertyValue></PropertyRow><PropertyRow><PropertyLabel>Source class</PropertyLabel><PropertyValue>{checkpoint.sourceKind} · {checkpoint.proofClass}</PropertyValue></PropertyRow><PropertyRow><PropertyLabel>Reason</PropertyLabel><PropertyValue>{checkpoint.reasonCode}</PropertyValue></PropertyRow></PropertyList></CardContent></Card>)}</div><ReadPagination label="Audit checkpoints" hasPrevious={checkpointPages.length > 1} hasNext={Boolean(checkpoints.data?.data.nextCursor)} onPrevious={() => setCheckpointPages((current) => current.length > 1 ? current.slice(0, -1) : current)} onNext={() => { const next = checkpoints.data?.data.nextCursor; if (next) setCheckpointPages((current) => [...current, next]); }} busy={checkpoints.isFetching} /></>}
    </section>
  </>;
}

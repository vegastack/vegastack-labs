"use client";

import { FieldHelp } from "@/components/field-help";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ReadPagination } from "@/components/read-pagination";
import { ReadViewState } from "@/components/read-view-state";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/ui/page-header";
import { PropertyList, PropertyLabel, PropertyRow, PropertyValue } from "@/components/ui/property-list";
import { classifyReadFailure } from "@/lib/read-queries";
import { phase5Queries } from "@/lib/phase5-queries";

function historyStatus(value: string): string {
  return ({ anchored: "Saved checkpoint", "pre-anchor": "Waiting for separate verification", incident: "History needs attention", verified: "Verified", pending: "Not yet verified", unknown: "Not checked", failed: "Verification failed" } as Record<string, string>)[value] ?? "Review recorded status";
}

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
    <PageHeader title="History checks" description="Check whether the saved operation history still matches its verification records. To see what an operation did, look it up in Changes." actions={<Button variant="outline" loading={checkpoints.isFetching || verification.isFetching} onClick={() => { void checkpoints.refetch(); void verification.refetch(); }}>Refresh History Checks</Button>} />
    <p className="text-sm text-muted-foreground">To inspect an operation result, open its run reference in <Link prefetch={false} href="/changes" className="underline">Changes</Link>.</p>
    {incident ? <ReadViewState kind="error" title="Audit incident" description="The recorded history did not pass verification. Keep the current records and follow the audit continuity runbook. Changes remain disabled." /> : null}
    <section className="space-y-3" aria-labelledby="audit-verification-title">
      <h2 id="audit-verification-title" className="text-h3">History verification</h2>
      {verification.isPending ? <ReadViewState kind="loading" title="Loading audit verification" description="Reading the saved history verification result." /> : verificationFailure ? <ReadViewState kind={verificationFailure} title="Audit verification unavailable" description="The history check could not be read. Refresh to try again; do not rely on an earlier result." onRetry={() => void verification.refetch()} /> : verificationData ? <Card><CardHeader className="flex flex-row items-center justify-between"><CardTitle>History status <FieldHelp label="History status">Audit history records who requested changes and their results. A checkpoint marks a verified section of that history. An independent match compares it with a separately recorded copy; it is not a machine health check.</FieldHelp></CardTitle><Badge bordered intent={incident ? "destructive" : verificationData.status === "anchored" && verificationData.proofClass === "live" && verificationData.independentMatch ? "success" : "warning"}>{incident ? "History needs attention" : verificationData.independentMatch && verificationData.proofClass === "live" ? "History verified" : "Not yet independently verified"}</Badge></CardHeader><CardContent><PropertyList><PropertyRow><PropertyLabel>Details</PropertyLabel><PropertyValue><details><summary className="cursor-pointer">Technical details</summary>Reason code: {verificationData.reasonCode}</details></PropertyValue></PropertyRow><PropertyRow><PropertyLabel>Matches the separate record</PropertyLabel><PropertyValue>{verificationData.independentMatch ? "yes" : "no"}</PropertyValue></PropertyRow><PropertyRow><PropertyLabel>Last verified history position</PropertyLabel><PropertyValue>{verificationData.lastAnchoredSequence}</PropertyValue></PropertyRow><PropertyRow><PropertyLabel>Next step</PropertyLabel><PropertyValue>{incident ? "Follow the history recovery procedure before making changes." : "Continue checking recorded operations; this result does not confirm machine or application health."}</PropertyValue></PropertyRow></PropertyList><details className="mt-3"><summary className="cursor-pointer">Technical details</summary><p>Reported status: {verificationData.status} · Next action: {verificationData.safeNextAction}</p><p>Source: {verificationData.sourceKind} · Proof class: {verificationData.proofClass}</p><p>State revision: {verificationData.stateRevision} · Recovery epoch: {verificationData.recoveryEpoch}</p></details></CardContent></Card> : null}
    </section>
    <section className="space-y-3" aria-labelledby="audit-checkpoints-title">
      <h2 id="audit-checkpoints-title" className="text-h3">Saved history checkpoints</h2>
      {checkpoints.isPending ? <ReadViewState kind="loading" title="Loading audit checkpoints" description="Reading saved history checkpoints." /> : checkpointFailure ? <ReadViewState kind={checkpointFailure} title="Saved history checkpoints unavailable" description="The saved history checkpoints could not be read. Refresh to try again." onRetry={() => void checkpoints.refetch()} /> : checkpoints.data?.data.items.length === 0 ? <ReadViewState kind="empty" title="No audit checkpoints" description="No saved history checkpoints are visible to your account." /> : <><div className="grid gap-3">{checkpoints.data?.data.items.map((checkpoint) => <Card key={checkpoint.checkpointId}><CardHeader className="flex flex-row items-center justify-between"><CardTitle className="font-mono text-base">{checkpoint.checkpointId}</CardTitle><Badge bordered intent={checkpoint.status === "incident" ? "destructive" : checkpoint.status === "anchored" && checkpoint.proofClass !== "fixture" ? "success" : "warning"}>{checkpoint.proofClass === "fixture" ? "Test data" : historyStatus(checkpoint.status)}</Badge></CardHeader><CardContent><PropertyList><PropertyRow><PropertyLabel>Events</PropertyLabel><PropertyValue>{checkpoint.firstEventId}–{checkpoint.lastEventId}</PropertyValue></PropertyRow><PropertyRow><PropertyLabel>Verification</PropertyLabel><PropertyValue>{historyStatus(checkpoint.verificationStatus)}</PropertyValue></PropertyRow><PropertyRow><PropertyLabel>Details</PropertyLabel><PropertyValue><details><summary className="cursor-pointer">Technical details</summary><p>Source: {checkpoint.sourceKind} · Proof class: {checkpoint.proofClass} · Status: {checkpoint.status}</p></details></PropertyValue></PropertyRow><PropertyRow><PropertyLabel>Details</PropertyLabel><PropertyValue><details><summary className="cursor-pointer">Technical details</summary>Reason code: {checkpoint.reasonCode}</details></PropertyValue></PropertyRow></PropertyList></CardContent></Card>)}</div><ReadPagination label="Saved history checkpoints" hasPrevious={checkpointPages.length > 1} hasNext={Boolean(checkpoints.data?.data.nextCursor)} onPrevious={() => setCheckpointPages((current) => current.length > 1 ? current.slice(0, -1) : current)} onNext={() => { const next = checkpoints.data?.data.nextCursor; if (next) setCheckpointPages((current) => [...current, next]); }} busy={checkpoints.isFetching} /></>}
    </section>
  </>;
}

"use client";

import { useQuery } from "@tanstack/react-query";
import type { GateView } from "@/generated/read-api";
import { ReadViewState } from "@/components/read-view-state";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { classifyReadFailure, readQueries } from "@/lib/read-queries";

const outcomeIntent = { passed: "success", blocked: "warning", stale: "warning", unknown: "default", "not-applicable": "default" } as const;

function GateRecords({ gates }: { gates: ReadonlyArray<GateView> }) {
  return <div className="grid gap-4" data-gate-records>{gates.map(view => {
    const { definition, evaluation, applicabilityReasonCode } = view;
    return <Card key={definition.gateId} data-gate-outcome={evaluation.outcome}>
      <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2"><CardTitle>{definition.gateId}</CardTitle><Badge bordered intent={outcomeIntent[evaluation.outcome]}>{evaluation.outcome}</Badge></CardHeader>
      <CardContent className="space-y-2 text-sm">
        <p>Reason: <span className="font-medium">{evaluation.reasonCode}</span></p>
        <p>Applicability: {applicabilityReasonCode}</p>
        <p>Evidence source: {evaluation.evidenceSource}</p>
        <p>Ready for input: {evaluation.readyForInput ? "yes" : "no"}</p>
        <p className="text-muted-foreground">This scope overview is derived from applied records. Check an exact subject with the local CLI; a draft or not-applicable result is not a passed gate.</p>
      </CardContent>
    </Card>;
  })}</div>;
}

export function GatesView() {
  const query = useQuery(readQueries.gates());
  if (query.isPending) return <ReadViewState kind="loading" title="Loading derived gates" description="Reading generated definitions and server-derived blockers." />;
  if (query.error) {
    const kind = classifyReadFailure(query.error, Boolean(query.data));
    const copy = kind === "denied" ? ["Gate status access denied", "Your current session cannot read derived gate state."] : kind === "unavailable" ? ["Gate status temporarily unavailable", "The gate read could not be reached; no result can be inferred."] : kind === "stale" ? ["Showing last known gate state", "This read failed temporarily; retained gate state may no longer be current."] : ["Gate status response rejected", "The response could not be used safely; no gate result can be inferred."];
    const retained = kind === "stale" && query.data ? <GateRecords gates={query.data.data.gates} /> : undefined;
    return <ReadViewState kind={kind} title={copy[0]} description={copy[1]} staleData={retained} onRetry={() => void query.refetch()} />;
  }
  const gates = query.data.data.gates;
  if (gates.length === 0) return <ReadViewState kind="empty" title="No gates in this read scope" description="The server returned no gate definitions for this scope. No gate pass can be inferred." />;
  return <GateRecords gates={gates} />;
}

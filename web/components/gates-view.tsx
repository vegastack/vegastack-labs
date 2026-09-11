"use client";

import { useQuery } from "@tanstack/react-query";
import { ReadViewState } from "@/components/read-view-state";
import { SourceStatus } from "@/components/source-status";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { classifyReadFailure, readQueries } from "@/lib/read-queries";

export function GatesView() {
  const query = useQuery(readQueries.sources({ limit: 1, source: "gates" }));
  if (query.isPending) return <ReadViewState kind="loading" title="Loading gate capability" description="Checking whether gate evaluation records are available." />;
  if (query.error) {
    const kind = classifyReadFailure(query.error, Boolean(query.data));
    const copy = kind === "denied" ? ["Gate status access denied", "Your current session cannot read gate capability status."] : kind === "unavailable" ? ["Gate status temporarily unavailable", "The gate source cannot currently be reached; no gate result can be inferred."] : kind === "stale" ? ["Showing last known gate capability", "The current gate source read failed temporarily."] : ["Gate status response rejected", "The response could not be used safely; no gate result can be inferred."];
    const staleSource = kind === "stale" && query.data?.data.items[0] ? <SourceStatus source={query.data.data.items[0]} /> : undefined;
    return <ReadViewState kind={kind} title={copy[0]} description={copy[1]} staleData={staleSource} onRetry={() => void query.refetch()} />;
  }
  const source = query.data.data.items[0];
  if (!source) return <ReadViewState kind="unknown" title="Gate capability is unknown" description="No gate source status was returned. No gate result can be inferred." />;
  return <Card><CardHeader><CardTitle>Gate evaluation capability</CardTitle></CardHeader><CardContent className="space-y-4"><SourceStatus source={source} /><ReadViewState kind={source.state === "failed" ? "error" : source.state === "stale" ? "stale" : source.state === "unknown" ? "unknown" : "unavailable"} title="Gate evaluation is not implemented" description="Detailed gate records and evidence arrive in their owning later phase. Use the local status command to inspect currently implemented service health; there is no manual gate control here." /></CardContent></Card>;
}

"use client";

import { useQuery } from "@tanstack/react-query";
import { ReadViewState } from "@/components/read-view-state";
import { SourceStatus } from "@/components/source-status";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { readQueries } from "@/lib/read-queries";

export function GatesView() {
  const query = useQuery(readQueries.sources({ limit: 1, source: "gates" }));
  if (query.isPending) return <ReadViewState kind="loading" title="Loading gate capability" description="Checking whether gate evaluation records are available." />;
  if (query.error) return <ReadViewState kind="denied" title="Gate status unavailable" description="This session cannot read gate capability status. Ask an administrator to review your grant." onRetry={() => void query.refetch()} />;
  const source = query.data.data.items[0];
  if (!source) return <ReadViewState kind="unknown" title="Gate capability is unknown" description="No gate source status was returned. No gate result can be inferred." />;
  return <Card><CardHeader><CardTitle>Gate evaluation capability</CardTitle></CardHeader><CardContent className="space-y-4"><SourceStatus source={source} /><ReadViewState kind={source.state === "failed" ? "error" : source.state === "stale" ? "stale" : source.state === "unknown" ? "unknown" : "unavailable"} title="Gate evaluation is not implemented" description="Detailed gate records and evidence arrive in their owning later phase. Use the local status command to inspect currently implemented service health; there is no manual gate control here." /></CardContent></Card>;
}

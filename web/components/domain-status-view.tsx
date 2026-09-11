"use client";

import { RefreshCw } from "lucide-react";
import { ReadViewState } from "@/components/read-view-state";
import { SourceStatus } from "@/components/source-status";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { type DomainStatusDefinition, useDomainStatus } from "@/lib/domain-status-queries";

export function DomainStatusView({ definition }: { definition: DomainStatusDefinition }) {
  const view = useDomainStatus(definition);
  if (view.state === "loading") return <ReadViewState kind="loading" title={`Loading ${definition.title} status`} description="Reading one authorized capability status." />;
  const sourceCard = view.source ? <DomainSourceCard definition={definition} source={view.source} refreshing={view.isRefreshing} refresh={view.refresh} /> : undefined;
  if (view.state === "current") return sourceCard;
  const copy = {
    denied: [`${definition.title} status access denied`, "Your current session cannot read this capability status."],
    unknown: [`${definition.title} status is unknown`, "No authorized source observation was returned, so no domain records or health can be inferred."],
    stale: [`Showing last known ${definition.title} status`, "The source observation is stale or a retryable temporary read failed. It does not prove current domain records."],
    unavailable: [`${definition.title} status unavailable`, definition.unavailableDescription],
    error: [`${definition.title} status could not be read`, "The response failed or could not be used safely. No domain records or operational result can be inferred."],
  }[view.state];
  return <ReadViewState kind={view.state} title={copy[0]} description={copy[1]} staleData={sourceCard} onRetry={view.refresh} />;
}

function DomainSourceCard({ definition, source, refreshing, refresh }: { definition: DomainStatusDefinition; source: NonNullable<ReturnType<typeof useDomainStatus>["source"]>; refreshing: boolean; refresh: () => void }) {
  return <Card><CardHeader><CardTitle>{definition.title} capability status</CardTitle></CardHeader><CardContent className="space-y-4"><SourceStatus source={source} /><p className="text-sm">{source.state === "healthy" ? `The status observation is current. ${definition.currentDescription}` : "This is capability status only; it is not a domain record or an operational result."}</p><p className="text-sm text-muted-foreground">Detailed records arrive in their owning later phase.</p><Button className="min-h-11" variant="outline" loading={refreshing} onClick={refresh}><RefreshCw aria-hidden />Refresh {definition.title}</Button></CardContent></Card>;
}

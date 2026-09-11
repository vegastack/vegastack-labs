"use client";

import { RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ReadViewState } from "@/components/read-view-state";
import { SourceStatus } from "@/components/source-status";
import { useOverview } from "@/lib/overview-queries";

export function OverviewView() {
  const view = useOverview();
  const content = view.summary ? <OverviewContent summary={view.summary} sources={view.sources} /> : undefined;
  if (view.state !== "success" && view.state !== "stale" && view.state !== "partial") {
    const copy = {
      loading: ["Loading Overview", "Reading the authorized local control-plane summary."],
      empty: ["No overview records", "The authorized summary returned no records."],
      denied: ["Overview access denied", "Your current session cannot read this scope. Ask an administrator to review your grant."],
      error: ["Overview could not be read", "The response could not be used safely. Refresh after the service is available."],
    }[view.state] ?? ["Overview unavailable", "No safe Overview response is available."];
    return <ReadViewState kind={view.state === "loading" || view.state === "empty" || view.state === "denied" ? view.state : "error"} title={copy[0]} description={copy[1]} onRetry={view.state === "loading" ? undefined : view.refresh} />;
  }
  return <div className="space-y-5">{view.state !== "success" ? <ReadViewState kind={view.state} title={view.state === "stale" ? "Showing last known Overview" : "Overview is partial"} description={view.state === "stale" ? "A temporary source failure occurred. Visible records are older authorized data." : "One authorized source could not be read."} staleData={content} onRetry={view.refresh} /> : content}<Button className="min-h-11" variant="outline" loading={view.isRefreshing} onClick={view.refresh}><RefreshCw aria-hidden />Refresh Overview</Button></div>;
}

function OverviewContent({ summary, sources }: { summary: NonNullable<ReturnType<typeof useOverview>["summary"]>; sources: ReturnType<typeof useOverview>["sources"] }) {
  return <div className="space-y-5" data-overview-records><div className="grid gap-3 sm:grid-cols-3"><Stat label="Database" value={summary.databaseMode} /><Stat label="Read access" value={summary.readAvailable ? "available" : "unavailable"} /><Stat label="Mutations" value={summary.mutationAvailable ? "available" : "unavailable"} /></div><p className="text-sm text-muted-foreground">State revision {summary.stateRevision} · Recovery epoch {summary.recoveryEpoch} · Drafts {summary.draftCount} ({summary.validDraftCount} valid, {summary.blockedDraftCount} blocked)</p><section aria-labelledby="source-heading"><h2 id="source-heading" className="mb-3 text-lg font-semibold">Domain sources</h2><div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">{sources.map(source => <Card key={source.id}><CardContent><SourceStatus source={source} /></CardContent></Card>)}</div></section></div>;
}

function Stat({ label, value }: { label: string; value: string }) { return <Card><CardHeader><CardTitle>{label}</CardTitle></CardHeader><CardContent className="capitalize">{value}</CardContent></Card>; }

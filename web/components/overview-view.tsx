"use client";

import { RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { PageHeader } from "@/components/ui/page-header";
import { Stat, StatLabel, StatValue } from "@/components/ui/stat";
import { ReadViewState } from "@/components/read-view-state";
import { SourceStatus } from "@/components/source-status";
import { overviewSourceIds, useOverview } from "@/lib/overview-queries";

type Overview = ReturnType<typeof useOverview>;

const stateCopy: Record<string, [string, string]> = {
  loading: ["Loading Overview", "Reading the authorized local control-plane summary."],
  empty: ["No overview records", "The authorized summary returned no records."],
  denied: ["Overview access denied", "Your current session cannot read this scope. Ask an administrator to review your grant."],
  unavailable: ["Overview unavailable", "The control-plane read service is temporarily unavailable. Local CLI recovery remains separate."],
  error: ["Overview could not be read", "The response could not be used safely. Refresh after the service is available."],
};

export function OverviewView() {
  const view = useOverview();
  const hasContent = Boolean(view.summary) || view.sources.length > 0 || view.state === "partial";
  const content = hasContent ? <OverviewContent summary={view.summary} sources={view.sources} /> : undefined;

  return (
    <>
      <PageHeader
        title="Overview"
        description="Authorized read-only summary of the local control plane and its domain sources."
        actions={
          <Button variant="outline" loading={view.isRefreshing} onClick={view.refresh}>
            <RefreshCw aria-hidden />
            Refresh Overview
          </Button>
        }
      />
      <OverviewBody view={view} content={content} />
    </>
  );
}

function OverviewBody({ view, content }: { view: Overview; content: React.ReactNode }) {
  if (view.state === "success") return <>{content}</>;
  if (view.state === "stale" || view.state === "partial") {
    return (
      <ReadViewState
        kind={view.state}
        title={view.state === "stale" ? "Showing last known Overview" : "Overview is partial"}
        description={
          view.state === "stale"
            ? "A temporary source failure occurred. Visible records are older authorized data."
            : "One authorized source could not be read."
        }
        staleData={content}
        onRetry={view.refresh}
      />
    );
  }
  const [title, description] = stateCopy[view.state] ?? ["Overview unavailable", "No safe Overview response is available."];
  const kind = view.state === "loading" || view.state === "empty" || view.state === "denied" || view.state === "unavailable" ? view.state : "error";
  return <ReadViewState kind={kind} title={title} description={description} onRetry={view.state === "loading" ? undefined : view.refresh} />;
}

function OverviewContent({ summary, sources }: { summary: Overview["summary"]; sources: Overview["sources"] }) {
  return (
    <div className="flex flex-col gap-8" data-overview-records>
      {summary ? (
        <section className="flex flex-col gap-3">
          <div className="grid gap-4 sm:grid-cols-3">
            <Stat>
              <StatLabel>Database</StatLabel>
              <StatValue className="capitalize">{summary.databaseMode.replace("-", " ")}</StatValue>
            </Stat>
            <Stat>
              <StatLabel>Read access</StatLabel>
              <StatValue>{summary.readAvailable ? "Available" : "Unavailable"}</StatValue>
            </Stat>
            <Stat>
              <StatLabel>Mutations</StatLabel>
              <StatValue>{summary.mutationAvailable ? "Available" : "Unavailable"}</StatValue>
            </Stat>
          </div>
          <p className="text-sm text-muted-foreground">
            State revision {summary.stateRevision} · Recovery epoch {summary.recoveryEpoch} · Drafts {summary.draftCount} ({summary.validDraftCount} valid, {summary.blockedDraftCount} blocked)
          </p>
        </section>
      ) : null}

      <section aria-labelledby="source-heading" className="flex flex-col gap-4">
        <h2 id="source-heading" className="text-h4 text-foreground">
          Domain sources
        </h2>
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {overviewSourceIds.map((id) => {
            const source = sources.find((candidate) => candidate.id === id);
            return (
              <Card key={id}>
                <CardContent>
                  {source ? (
                    <SourceStatus source={source} />
                  ) : (
                    <div className="flex flex-col gap-1.5" data-source-state="unknown">
                      <p className="text-sm font-medium capitalize text-foreground">{id}</p>
                      <p className="text-sm text-muted-foreground">Not returned — no health can be inferred.</p>
                    </div>
                  )}
                </CardContent>
              </Card>
            );
          })}
        </div>
      </section>
    </div>
  );
}

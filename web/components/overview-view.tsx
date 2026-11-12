"use client";

import { RefreshCw } from "lucide-react";
import Link from "next/link";
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
        description="Check the controller and open the records you need."
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
              <StatLabel>Controller database</StatLabel>
              <StatValue className="capitalize">{summary.databaseMode.replace("-", " ")}</StatValue>
            </Stat>
            <Stat>
              <StatLabel>Read access</StatLabel>
              <StatValue>{summary.readAvailable ? "Available" : "Unavailable"}</StatValue>
            </Stat>
            <Stat>
              <StatLabel>Change engine</StatLabel>
              <StatValue>{summary.mutationAvailable ? "Ready for review" : "Read-only"}</StatValue>
            </Stat>
          </div>
          <p className="text-sm text-muted-foreground">Each change still requires its own permissions, checks and approval.</p>
          <details className="text-sm text-muted-foreground">
            <summary className="cursor-pointer">Technical details</summary>
            <p>State revision {summary.stateRevision} · Recovery epoch {summary.recoveryEpoch} · Drafts {summary.draftCount} ({summary.validDraftCount} valid, {summary.blockedDraftCount} blocked)</p>
          </details>
        </section>
      ) : null}

      <section aria-label="Common tasks" className="grid gap-4 sm:grid-cols-3">
        {[
          { href: "/nodes", title: "Inspect nodes", description: "See registered machines and prepare onboarding." },
          { href: "/services", title: "Inspect services", description: "Read application settings and recorded deployment results." },
          { href: "/changes", title: "Inspect or prepare a change", description: "Open an existing run or review a proposed operation." },
        ].map(task => <Card key={task.href}><CardContent><Link prefetch={false} href={task.href} className="font-medium underline">{task.title}</Link><p className="mt-2 text-sm text-muted-foreground">{task.description}</p></CardContent></Card>)}
      </section>

      <section aria-labelledby="source-heading" className="flex flex-col gap-4">
        <h2 id="source-heading" className="text-h4 text-foreground">
          Recorded information
        </h2>
        <p className="text-sm text-muted-foreground">These are controller records, not live health checks of your machines or applications. Open a page to inspect its details.</p>
        {sources.some(source => source.state === "failed") ? <p role="status" className="text-sm text-destructive">A source reported a collection failure. Open collection details for its recorded status.</p> : null}
        <details>
        <summary className="cursor-pointer text-sm font-medium">Collection details</summary>
        <div className="mt-4 grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
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
                      <p className="text-sm text-muted-foreground">No record was returned in your current access scope.</p>
                    </div>
                  )}
                  {id !== "database" ? <Link prefetch={false} className="mt-3 inline-block text-sm underline" href={`/${id}`}>Open {id.charAt(0).toUpperCase() + id.slice(1)}</Link> : null}
                </CardContent>
              </Card>
            );
          })}
        </div>
        </details>
      </section>
    </div>
  );
}

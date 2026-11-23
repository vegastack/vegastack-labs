"use client";

import { FieldHelp } from "@/components/field-help";
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
  loading: ["Loading Overview", "Reading your saved records and server status."],
  empty: ["No overview records", "No overview information is available to your account yet."],
  denied: ["Overview access denied", "Your account cannot view this information. Ask an administrator for access."],
  unavailable: ["Overview unavailable", "The Labs server could not return this information. Refresh to try again; ask an administrator if it keeps failing."],
  error: ["Overview could not be read", "The server response could not be checked. Refresh to try again."],
};

export function OverviewView() {
  const view = useOverview();
  const hasContent = Boolean(view.summary) || view.sources.length > 0 || view.state === "partial";
  const content = hasContent ? <OverviewContent summary={view.summary} sources={view.sources} /> : undefined;

  return (
    <>
      <PageHeader
        title="Overview"
        description="Start with Nodes to view or add a computer, Services to inspect an application, or Changes to review a proposed operation."
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
            ? "Some information could not be refreshed. The records shown are from the last successful read."
            : "Some information could not be loaded. You can still use the sections shown below."
        }
        staleData={content}
        onRetry={view.refresh}
      />
    );
  }
  const [title, description] = stateCopy[view.state] ?? ["Overview unavailable", "The overview could not be loaded. Refresh to try again."];
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
              <StatLabel>Saved records <FieldHelp label="Saved records">The database stores machine records, settings and operation history on the management server. This status describes those records, not your applications.</FieldHelp></StatLabel>
              <StatValue className="capitalize">{summary.databaseMode.replace("-", " ")}</StatValue>
            </Stat>
            <Stat>
              <StatLabel>Read access</StatLabel>
              <StatValue>{summary.readAvailable ? "Available" : "Unavailable"}</StatValue>
            </Stat>
            <Stat>
              <StatLabel>Changes <FieldHelp label="Changes">Ready for review means the server can prepare changes. Each operation still needs its own checks and approval before it runs.</FieldHelp></StatLabel>
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
          { href: "/nodes", title: "View machines", description: "See saved computers and start adding a machine." },
          { href: "/services", title: "View applications", description: "Read application settings and the last recorded deployment result." },
          { href: "/changes", title: "Inspect or prepare a change", description: "Open an existing run or review a proposed operation." },
        ].map(task => <Card key={task.href}><CardContent><Link prefetch={false} href={task.href} className="font-medium underline">{task.title}</Link><p className="mt-2 text-sm text-muted-foreground">{task.description}</p></CardContent></Card>)}
      </section>

      <section aria-labelledby="source-heading" className="flex flex-col gap-4">
        <h2 id="source-heading" className="text-h4 text-foreground">
          Recorded information
        </h2>
        <p className="text-sm text-muted-foreground">These are saved records, not live health checks. Open Nodes or Services to inspect a machine or application.</p>
        {sources.some(source => source.state === "failed") ? <p role="status" className="text-sm text-destructive">Some information could not be collected. Expand the collection details below to see which section needs attention.</p> : null}
        <details>
        <summary className="cursor-pointer text-sm font-medium">When information was last collected</summary>
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
                      <p className="text-sm text-muted-foreground">No information is available to your account for this section.</p>
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

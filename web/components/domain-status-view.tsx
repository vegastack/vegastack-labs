"use client";

import { RefreshCw } from "lucide-react";
import { useEffect, useRef } from "react";
import { PageHeader } from "@/components/ui/page-header";
import { ReadViewState } from "@/components/read-view-state";
import { SourceStatus } from "@/components/source-status";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PropertyList, PropertyLabel, PropertyRow, PropertyValue } from "@/components/ui/property-list";
import { type DomainStatusDefinition, useDomainStatus } from "@/lib/domain-status-queries";

export function DomainStatusView({ definition }: { definition: DomainStatusDefinition }) {
  const view = useDomainStatus(definition);
  const refreshButton = useRef<HTMLButtonElement>(null);
  const restoreRefreshFocus = useRef(false);
  useEffect(() => {
    if (!view.isRefreshing && restoreRefreshFocus.current) {
      restoreRefreshFocus.current = false;
      refreshButton.current?.focus();
    }
  }, [view.isRefreshing, view.state]);

  const sourceCard = view.source ? <DomainSourceCard definition={definition} source={view.source} /> : undefined;

  let body: React.ReactNode;
  if (view.state === "loading") {
    body = <ReadViewState kind="loading" title={`Loading ${definition.title} status`} description="Reading one authorized capability status." />;
  } else if (view.state === "current") {
    body = sourceCard;
  } else {
    const copy = {
      denied: [`${definition.title} status access denied`, "Your current session cannot read this capability status."],
      unknown: [`${definition.title} status is unknown`, "No authorized source observation was returned, so no domain records or health can be inferred."],
      stale: [`Showing last known ${definition.title} status`, "The source observation is stale or a retryable temporary read failed. It does not prove current domain records."],
      unavailable: [`${definition.title} status unavailable`, definition.unavailableDescription],
      error: [`${definition.title} status could not be read`, "The response failed or could not be used safely. No domain records or operational result can be inferred."],
    }[view.state];
    body = <ReadViewState kind={view.state} title={copy[0]} description={copy[1]} staleData={sourceCard} />;
  }

  return (
    <>
      <PageHeader
        title={definition.title}
        description={`Read-only ${definition.title.toLowerCase()} capability status from the authorized control plane.`}
        actions={
          <Button
            ref={refreshButton}
            variant="outline"
            loading={view.isRefreshing}
            onClick={() => {
              restoreRefreshFocus.current = true;
              view.refresh();
            }}
          >
            <RefreshCw aria-hidden />
            Refresh {definition.title}
          </Button>
        }
      />
      {body}
    </>
  );
}

function DomainSourceCard({
  definition,
  source,
}: {
  definition: DomainStatusDefinition;
  source: NonNullable<ReturnType<typeof useDomainStatus>["source"]>;
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{definition.title} capability status</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <PropertyList>
          <PropertyRow>
            <PropertyLabel>Capability</PropertyLabel>
            <PropertyValue className="font-mono text-xs">{source.capability}</PropertyValue>
          </PropertyRow>
        </PropertyList>
        <SourceStatus source={source} />
        <p className="text-sm text-muted-foreground">
          {source.state === "healthy"
            ? `The status observation is current. ${definition.currentDescription}`
            : "This is capability status only; it is not a domain record or an operational result."}
          {" "}Detailed records arrive in their owning later phase.
        </p>
      </CardContent>
    </Card>
  );
}

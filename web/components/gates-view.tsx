"use client";

import { useQuery } from "@tanstack/react-query";
import { RefreshCw } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/ui/page-header";
import { ReadViewState } from "@/components/read-view-state";
import { SourceStatus } from "@/components/source-status";
import { classifyReadFailure, readQueries } from "@/lib/read-queries";

export function GatesView() {
  const query = useQuery(readQueries.sources({ limit: 1, source: "gates" }));
  const source = query.data?.data.items[0];

  let body: React.ReactNode;
  if (query.isPending) {
    body = <ReadViewState kind="loading" title="Loading gate capability" description="Checking whether gate evaluation records are available." />;
  } else if (query.error) {
    const kind = classifyReadFailure(query.error, Boolean(query.data));
    const copy =
      kind === "denied"
        ? ["Gate status access denied", "Your current session cannot read gate capability status."]
        : kind === "unavailable"
          ? ["Gate status temporarily unavailable", "The gate source cannot currently be reached; no gate result can be inferred."]
          : kind === "stale"
            ? ["Showing last known gate capability", "The current gate source read failed temporarily."]
            : ["Gate status response rejected", "The response could not be used safely; no gate result can be inferred."];
    const staleSource = kind === "stale" && source ? <SourceStatus source={source} /> : undefined;
    body = <ReadViewState kind={kind} title={copy[0]} description={copy[1]} staleData={staleSource} onRetry={() => void query.refetch()} />;
  } else if (!source) {
    body = <ReadViewState kind="unknown" title="Gate capability is unknown" description="No gate source status was returned. No gate result can be inferred." />;
  } else {
    body = (
      <Card>
        <CardHeader>
          <CardTitle>Gate evaluation capability</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <SourceStatus source={source} />
          <Alert intent="info">
            <AlertTitle>Gate evaluation is not implemented</AlertTitle>
            <AlertDescription>
              Detailed gate records and evidence arrive in their owning later phase. Use the local status command to inspect currently
              implemented service health; there is no manual gate control here.
            </AlertDescription>
          </Alert>
        </CardContent>
      </Card>
    );
  }

  return (
    <>
      <PageHeader
        title="Gates"
        description="Read-only capability status for gate evaluation. Detailed gate records arrive in a later phase."
        actions={
          <Button variant="outline" loading={query.isFetching} onClick={() => void query.refetch()}>
            <RefreshCw aria-hidden />
            Refresh Gates
          </Button>
        }
      />
      {body}
    </>
  );
}

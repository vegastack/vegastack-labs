"use client";
import { useQuery } from "@tanstack/react-query";
import { PageHeader } from "@/components/ui/page-header";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ReadViewState } from "@/components/read-view-state";
import { readClient } from "@/lib/read-client";
import { classifyReadFailure } from "@/lib/read-queries";
const providerLabels: Record<string, string> = {
  identity: "Browser sign-in",
  acknowledgement: "Slack approvals",
  "backup.local": "Local backups",
  "backup.offsite": "Offsite backups",
};

export function ProvidersView() {
  const view = useQuery({
    queryKey: ["read", "sources", { source: "providers", records: true }],
    queryFn: ({ signal }) => readClient.listProviders({ signal }),
  });
  const state = view.error
    ? classifyReadFailure(view.error, Boolean(view.data))
    : view.isPending
      ? "loading"
      : "current";
  const data =
    state === "current" || state === "stale" ? view.data?.data : undefined;
  return (
    <>
      <PageHeader
        title="Providers"
        description="Configured adapter capabilities. Configuration does not prove connectivity or workload readiness."
        actions={
          <Button
            variant="outline"
            loading={view.isFetching}
            onClick={() => void view.refetch()}
          >
            Refresh Providers
          </Button>
        }
      />
      {state !== "current" ? (
        <ReadViewState
          kind={state}
          title={
            state === "denied"
              ? "Provider access denied"
              : state === "loading"
                ? "Loading providers"
                : state === "stale"
                  ? "Showing last known provider configuration"
                  : "Providers could not be read"
          }
          description="Configuration alone does not confirm a working connection."
        />
      ) : null}
      {data ? (
        <ul
          aria-label="Provider capabilities"
          className="grid gap-4 sm:grid-cols-2"
        >
          {data.providers.map((p) => (
            <li key={p.capability}>
              <Card>
                <CardHeader>
                  <CardTitle>{providerLabels[p.capability] ?? p.capability}</CardTitle>
                </CardHeader>
                <CardContent className="space-y-2">
                  <p>{p.configured ? "Configured" : "Not configured"}</p>
                  <p>Connectivity: {p.connectivity}</p>
                  {p.configured ? (
                    <p className="text-sm text-muted-foreground">
                      No current connectivity observation is available.
                    </p>
                  ) : (
                    <p className="text-sm text-muted-foreground">
                      This capability is unavailable until configured through an
                      approved workflow.
                    </p>
                  )}
                </CardContent>
              </Card>
            </li>
          ))}
        </ul>
      ) : null}
    </>
  );
}

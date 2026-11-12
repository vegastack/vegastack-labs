"use client";
import { FieldHelp } from "@/components/field-help";
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
        title="Connections"
        description="See which outside services are set up for sign-in, approvals and backups. Check the connection status before relying on one."
        actions={
          <Button
            variant="outline"
            loading={view.isFetching}
            onClick={() => void view.refetch()}
          >
            Refresh Connections
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
      {data && data.providers.length === 0 ? <ReadViewState kind="empty" title="No connections visible" description="No provider configuration is visible in your current read scope. This does not establish whether providers are connected or healthy." /> : null}
      {data && data.providers.length > 0 ? (
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
                  <p>{p.configured ? "Settings saved" : "Not set up"} <FieldHelp label="Provider setup">A provider is an outside service used by this Console. Settings saved means its configuration exists; a separate connection check is needed to confirm it works.</FieldHelp></p>
                  <p>Connection status: {p.connectivity === "unknown" ? "Not checked" : "Unavailable"}</p>
                  {p.configured ? (
                    <p className="text-sm text-muted-foreground">
                      No current connectivity observation is available.
                    </p>
                  ) : (
                    <p className="text-sm text-muted-foreground">
                      Ask an administrator to set up this connection through an approved change.
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

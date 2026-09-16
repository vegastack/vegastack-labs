"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { RefreshCw } from "lucide-react";
import { useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Item, ItemActions, ItemContent, ItemGroup, ItemTitle } from "@/components/ui/item";
import { PageHeader } from "@/components/ui/page-header";
import { PropertyList, PropertyLabel, PropertyRow, PropertyValue } from "@/components/ui/property-list";
import { ReadDetail } from "@/components/read-detail";
import { ReadPagination } from "@/components/read-pagination";
import { useReadFailure } from "@/components/query-provider";
import { ReadViewState } from "@/components/read-view-state";
import { formatConsoleTime, SourceStatus } from "@/components/source-status";
import { readClient } from "@/lib/read-client";
import { useNodeRecords } from "@/lib/node-queries";
import { classifyReadFailure, mayRetainStaleData } from "@/lib/read-queries";

type Kind = "nodes" | "aliases" | "observations";
type Selection = { kind: Kind; id: string } | null;
const SINGULAR = { nodes: "node", aliases: "alias", observations: "observation" } as const;

function Header({ view }: { view?: { refresh: () => void; busy: boolean } }) {
  return (
    <PageHeader
      title="Nodes"
      description="The newest authorized inventory draft and its declared nodes, aliases, and observations."
      actions={
        view ? (
          <Button variant="outline" loading={view.busy} onClick={view.refresh}>
            <RefreshCw aria-hidden />
            Refresh Nodes
          </Button>
        ) : undefined
      }
    />
  );
}

export function NodesView() {
  const queryClient = useQueryClient();
  const { failure, clearFailure } = useReadFailure("inventory");
  const records = useNodeRecords();
  const [selection, setSelection] = useState<Selection>(null);
  const trigger = useRef<HTMLButtonElement | null>(null);
  const detailPath = selection && records.reference ? { ...records.reference, recordId: selection.id } : undefined;
  const nodeDetail = useQuery({ queryKey: ["read", "detail", "nodes", detailPath], enabled: selection?.kind === "nodes", queryFn: ({ signal }) => readClient.getInventoryDraftNode(detailPath!, { signal }) });
  const aliasDetail = useQuery({ queryKey: ["read", "detail", "aliases", detailPath], enabled: selection?.kind === "aliases", queryFn: ({ signal }) => readClient.getInventoryDraftAlias(detailPath!, { signal }) });
  const observationDetail = useQuery({ queryKey: ["read", "detail", "observations", detailPath], enabled: selection?.kind === "observations", queryFn: ({ signal }) => readClient.getInventoryDraftObservation(detailPath!, { signal }) });
  const detail = selection?.kind === "nodes" ? nodeDetail : selection?.kind === "aliases" ? aliasDetail : observationDetail;

  const recoverFailure = async () => {
    clearFailure();
    await queryClient.refetchQueries({ queryKey: ["read"], type: "active" });
  };
  const refresh = async () => {
    clearFailure();
    await queryClient.cancelQueries({ queryKey: ["read"] });
    await Promise.all([records.draft.refetch(), records.source.refetch(), records.collections.nodes.refetch(), records.collections.aliases.refetch(), records.collections.observations.refetch()]);
  };

  if (failure) return <NodesShell><NodeFailure error={failure} retained={false} onRetry={() => void recoverFailure()} /></NodesShell>;
  if (records.draft.isPending) return <NodesShell busy><ReadViewState kind="loading" title="Loading Nodes" description="Finding the newest authorized inventory draft." /></NodesShell>;
  if (records.draft.error) return <NodesShell><NodeFailure error={records.draft.error} retained={Boolean(records.draft.data)} onRetry={() => void records.draft.refetch()} /></NodesShell>;
  if (!records.reference) return <NodesShell><ReadViewState kind="empty" title="No inventory draft" description="Import and qualification actions are not available in this read-only Console." /></NodesShell>;

  const related = [records.source, records.collections.nodes, records.collections.aliases, records.collections.observations, ...(selection ? [detail] : [])];
  const hardFailure = related.find((query) => query.error && !mayRetainStaleData(query.error));
  if (hardFailure?.error) return <NodesShell><NodeFailure error={hardFailure.error} retained={Boolean(hardFailure.data)} onRetry={() => void hardFailure.refetch()} /></NodesShell>;
  const stale = related.some((query) => query.error && classifyReadFailure(query.error, Boolean(query.data)) === "stale");
  const partial = related.some((query) => query.error && mayRetainStaleData(query.error) && !query.data);

  const draft = records.draft.data!.data.items[0]!;
  const nodeSource = records.source.data?.data.items[0];
  const singular = selection ? SINGULAR[selection.kind] : "record";
  const busy = related.some((query) => query.isFetching);

  return (
    <NodesShell busy={busy} refresh={() => void refresh()}>
      {partial || stale ? (
        <ReadViewState
          kind={partial ? "partial" : "stale"}
          title={partial ? "Node records are partial" : "Showing last known node records"}
          description={partial ? "At least one temporary source failure has no older authorized page to show." : "A temporary read failure occurred. Visible records are older authorized data."}
          onRetry={() => void refresh()}
        />
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle>Draft inventory</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <div className="flex flex-wrap items-center gap-2">
            <Badge intent="info" size="lg">Revision {draft.revision}</Badge>
            <Badge intent={draft.validationStatus === "valid" ? "success" : "warning"} size="lg" className="capitalize">{draft.validationStatus}</Badge>
            <Badge variant="outline" size="lg">Declared authority</Badge>
          </div>
          <p className="text-sm text-muted-foreground">Qualification is unavailable until its owning phase supplies verified records.</p>
          {nodeSource ? <SourceStatus source={nodeSource} /> : <p className="text-sm text-muted-foreground" data-source-state="unknown">Node source status is unknown; no health can be inferred.</p>}
        </CardContent>
      </Card>

      {(["nodes", "aliases", "observations"] as const).map((kind) => (
        <RecordSection
          key={kind}
          kind={kind}
          title={kind[0].toUpperCase() + kind.slice(1)}
          heading={kind !== "nodes"}
          items={records.collections[kind].data?.data.items ?? []}
          error={records.collections[kind].error}
          next={records.collections[kind].data?.data.nextCursor ?? null}
          back={records.pages[kind].back.length > 0}
          busy={records.collections[kind].isFetching}
          move={records.move}
          select={(k, id, element) => {
            trigger.current = element;
            setSelection({ kind: k, id });
          }}
        />
      ))}

      <ReadDetail title={`${singular} details`} open={Boolean(selection)} onOpenChange={(open) => !open && setSelection(null)} returnFocusRef={trigger}>
        {detail.isPending ? (
          <p role="status" className="text-sm text-muted-foreground">Loading authorized details…</p>
        ) : detail.error ? (
          <p role="alert" className="text-sm text-destructive-text">Record details could not be read safely.</p>
        ) : detail.data ? (
          <PropertyList>
            {Object.entries(detail.data.data).map(([key, value]) => (
              <PropertyRow key={key}>
                <PropertyLabel>{key}</PropertyLabel>
                <PropertyValue className="break-words">{formatDetailValue(key, value)}</PropertyValue>
              </PropertyRow>
            ))}
          </PropertyList>
        ) : null}
      </ReadDetail>
    </NodesShell>
  );
}

function NodesShell({ children, busy = false, refresh }: { children: React.ReactNode; busy?: boolean; refresh?: () => void }) {
  return (
    <>
      <Header view={refresh ? { busy, refresh } : undefined} />
      <div className="min-w-0 space-y-6">{children}</div>
    </>
  );
}

function formatDetailValue(key: string, value: unknown): string {
  if (value === null) return "Not available";
  if (typeof value === "string" && key.endsWith("At")) return formatConsoleTime(value);
  return String(value);
}

function NodeFailure({ error, retained, onRetry }: { error: unknown; retained: boolean; onRetry: () => void }) {
  const kind = classifyReadFailure(error, retained);
  const copy = kind === "denied"
    ? ["Nodes access denied", "Your current session cannot read this inventory scope."]
    : kind === "unavailable"
      ? ["Nodes temporarily unavailable", "The read service cannot be reached. Local CLI recovery remains separate."]
      : kind === "stale"
        ? ["Showing last known node records", "A temporary read failure occurred."]
        : ["Nodes response rejected", "The response could not be used safely."];
  return <ReadViewState kind={kind} title={copy[0]} description={copy[1]} onRetry={onRetry} />;
}

function RecordSection({
  kind,
  title,
  heading = true,
  items,
  error,
  next,
  back,
  busy,
  move,
  select,
}: {
  kind: Kind;
  title: string;
  // The page `PageHeader` already renders the "Nodes" h1, so the nodes collection
  // suppresses its own heading (heading=false) to keep exactly one "Nodes" heading;
  // aliases and observations keep theirs.
  heading?: boolean;
  items: readonly { id: string }[];
  error: unknown;
  next: string | null;
  back: boolean;
  busy: boolean;
  move: (kind: Kind, next: string | null | "back") => void;
  select: (kind: Kind, id: string, element: HTMLButtonElement) => void;
}) {
  const singular = SINGULAR[kind];
  return (
    <section {...(heading ? { "aria-labelledby": `${kind}-heading` } : { "aria-label": title })} className="flex flex-col gap-3">
      <div className="flex items-center justify-between gap-3">
        {heading ? <h2 id={`${kind}-heading`} className="text-h4 text-foreground">{title}</h2> : <span className="text-label text-muted-foreground">{title}</span>}
        {items.length > 0 ? <Badge variant="soft" intent="default">{items.length}</Badge> : null}
      </div>
      {busy && items.length === 0 ? (
        <ReadViewState kind="loading" title={`Loading ${title}`} description="Reading an authorized server page." />
      ) : error && items.length === 0 ? (
        <ReadViewState kind="unavailable" title={`${title} temporarily unavailable`} description="This authorized page could not be read; no empty result is inferred." />
      ) : items.length === 0 ? (
        <ReadViewState kind="empty" title={`No ${title.toLowerCase()}`} description="This draft contains no authorized records in this collection." />
      ) : (
        <Card>
          <ItemGroup>
            {items.map((item) => (
              <Item key={item.id} size="sm">
                <ItemContent>
                  <ItemTitle className="font-mono text-sm">{item.id}</ItemTitle>
                </ItemContent>
                <ItemActions>
                  <Button variant="ghost" size="sm" onClick={(event) => select(kind, item.id, event.currentTarget)}>
                    View {singular}
                  </Button>
                </ItemActions>
              </Item>
            ))}
          </ItemGroup>
        </Card>
      )}
      <ReadPagination label={title} hasPrevious={back} hasNext={Boolean(next)} busy={busy} onPrevious={() => move(kind, "back")} onNext={() => move(kind, next)} />
    </section>
  );
}

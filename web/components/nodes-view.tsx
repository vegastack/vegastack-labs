"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
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
  if (failure) return <NodeFailure error={failure} retained={false} onRetry={() => void recoverFailure()} />;
  if (records.draft.isPending) return <ReadViewState kind="loading" title="Loading Nodes" description="Finding the newest authorized inventory draft." />;
  if (records.draft.error) return <NodeFailure error={records.draft.error} retained={Boolean(records.draft.data)} onRetry={() => void records.draft.refetch()} />;
  if (!records.reference) return <ReadViewState kind="empty" title="No inventory draft" description="Import and qualification actions are not available in this read-only Console." />;
  const related = [records.source, records.collections.nodes, records.collections.aliases, records.collections.observations, ...(selection ? [detail] : [])];
  const hardFailure = related.find(query => query.error && !mayRetainStaleData(query.error));
  if (hardFailure?.error) return <NodeFailure error={hardFailure.error} retained={Boolean(hardFailure.data)} onRetry={() => void hardFailure.refetch()} />;
  const stale = related.some(query => query.error && classifyReadFailure(query.error, Boolean(query.data)) === "stale");
  const partial = related.some(query => query.error && mayRetainStaleData(query.error) && !query.data);
  const refresh = async () => {
    clearFailure();
    await queryClient.cancelQueries({ queryKey: ["read"] });
    await Promise.all([records.draft.refetch(), records.source.refetch(), records.collections.nodes.refetch(), records.collections.aliases.refetch(), records.collections.observations.refetch()]);
  };
  const draft = records.draft.data!.data.items[0]!;
  const singular = selection ? ({ nodes: "node", aliases: "alias", observations: "observation" } as const)[selection.kind] : "record";
  return <div className="space-y-5">{partial || stale ? <ReadViewState kind={partial ? "partial" : "stale"} title={partial ? "Node records are partial" : "Showing last known node records"} description={partial ? "At least one temporary source failure has no older authorized page to show." : "A temporary read failure occurred. Visible records are older authorized data."} onRetry={() => void refresh()} /> : null}<Card><CardHeader><CardTitle>Draft inventory</CardTitle></CardHeader><CardContent className="space-y-2"><p>Revision {draft.revision} · {draft.validationStatus} · declared authority</p><p className="text-sm text-muted-foreground">Qualification is unavailable until its owning phase supplies verified records.</p>{records.source.data?.data.items[0] ? <SourceStatus source={records.source.data.data.items[0]} /> : <p className="text-sm" data-source-state="unknown">Node source status is unknown; no health can be inferred.</p>}</CardContent></Card><RecordSection kind="nodes" title="Nodes" items={records.collections.nodes.data?.data.items ?? []} error={records.collections.nodes.error} next={records.collections.nodes.data?.data.nextCursor ?? null} back={records.pages.nodes.back.length > 0} busy={records.collections.nodes.isFetching} move={records.move} select={(kind, id, element) => { trigger.current = element; setSelection({ kind, id }); }} /><RecordSection kind="aliases" title="Aliases" items={records.collections.aliases.data?.data.items ?? []} error={records.collections.aliases.error} next={records.collections.aliases.data?.data.nextCursor ?? null} back={records.pages.aliases.back.length > 0} busy={records.collections.aliases.isFetching} move={records.move} select={(kind, id, element) => { trigger.current = element; setSelection({ kind, id }); }} /><RecordSection kind="observations" title="Observations" items={records.collections.observations.data?.data.items ?? []} error={records.collections.observations.error} next={records.collections.observations.data?.data.nextCursor ?? null} back={records.pages.observations.back.length > 0} busy={records.collections.observations.isFetching} move={records.move} select={(kind, id, element) => { trigger.current = element; setSelection({ kind, id }); }} /><Button className="min-h-11" variant="outline" loading={related.some(query => query.isFetching)} onClick={() => void refresh()}>Refresh Nodes</Button><ReadDetail title={`${singular} details`} open={Boolean(selection)} onOpenChange={open => !open && setSelection(null)} returnFocusRef={trigger}>{detail.isPending ? <p role="status">Loading authorized details…</p> : detail.error ? <p role="alert">Record details could not be read safely.</p> : <dl className="grid gap-2">{detail.data ? Object.entries(detail.data.data).map(([key, value]) => <div key={key}><dt className="text-sm font-medium">{key}</dt><dd className="break-words text-sm text-muted-foreground">{formatDetailValue(key, value)}</dd></div>) : null}</dl>}</ReadDetail></div>;
}

function formatDetailValue(key: string, value: unknown): string {
  if (value === null) return "Not available";
  if (typeof value === "string" && key.endsWith("At")) return formatConsoleTime(value);
  return String(value);
}

function NodeFailure({ error, retained, onRetry }: { error: unknown; retained: boolean; onRetry: () => void }) {
  const kind = classifyReadFailure(error, retained);
  const copy = kind === "denied" ? ["Nodes access denied", "Your current session cannot read this inventory scope."] : kind === "unavailable" ? ["Nodes temporarily unavailable", "The read service cannot be reached. Local CLI recovery remains separate."] : kind === "stale" ? ["Showing last known node records", "A temporary read failure occurred."] : ["Nodes response rejected", "The response could not be used safely."];
  return <ReadViewState kind={kind} title={copy[0]} description={copy[1]} onRetry={onRetry} />;
}

function RecordSection({ kind, title, items, error, next, back, busy, move, select }: { kind: Kind; title: string; items: readonly { id: string }[]; error: unknown; next: string | null; back: boolean; busy: boolean; move: (kind: Kind, next: string | null | "back") => void; select: (kind: Kind, id: string, element: HTMLButtonElement) => void }) {
  const singular = ({ nodes: "node", aliases: "alias", observations: "observation" } as const)[kind];
  return <section aria-labelledby={`${kind}-heading`} className="space-y-3"><h2 id={`${kind}-heading`} className="text-lg font-semibold">{title}</h2>{busy && items.length === 0 ? <ReadViewState kind="loading" title={`Loading ${title}`} description="Reading an authorized server page." /> : error && items.length === 0 ? <ReadViewState kind="unavailable" title={`${title} temporarily unavailable`} description="This authorized page could not be read; no empty result is inferred." /> : items.length === 0 ? <ReadViewState kind="empty" title={`No ${title.toLowerCase()}`} description="This draft contains no authorized records in this collection." /> : <div className="grid gap-2 sm:grid-cols-2">{items.map(item => <Card key={item.id} size="sm"><CardContent className="flex items-center justify-between gap-3"><span className="min-w-0 truncate">{item.id}</span><Button className="min-h-11" variant="outline" onClick={event => select(kind, item.id, event.currentTarget)}>View {singular}</Button></CardContent></Card>)}</div>}<ReadPagination label={title} hasPrevious={back} hasNext={Boolean(next)} busy={busy} onPrevious={() => move(kind, "back")} onNext={() => move(kind, next)} /></section>;
}

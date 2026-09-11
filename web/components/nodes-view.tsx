"use client";

import { useQuery } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ReadDetail } from "@/components/read-detail";
import { ReadPagination } from "@/components/read-pagination";
import { ReadViewState } from "@/components/read-view-state";
import { SourceStatus } from "@/components/source-status";
import { readClient } from "@/lib/read-client";
import { useNodeRecords } from "@/lib/node-queries";

type Kind = "nodes" | "aliases" | "observations";
type Selection = { kind: Kind; id: string } | null;

export function NodesView() {
  const records = useNodeRecords();
  const [selection, setSelection] = useState<Selection>(null);
  const trigger = useRef<HTMLButtonElement | null>(null);
  const detailPath = selection && records.reference ? { ...records.reference, recordId: selection.id } : undefined;
  const nodeDetail = useQuery({ queryKey: ["read", "detail", "nodes", detailPath], enabled: selection?.kind === "nodes", queryFn: ({ signal }) => readClient.getInventoryDraftNode(detailPath!, { signal }) });
  const aliasDetail = useQuery({ queryKey: ["read", "detail", "aliases", detailPath], enabled: selection?.kind === "aliases", queryFn: ({ signal }) => readClient.getInventoryDraftAlias(detailPath!, { signal }) });
  const observationDetail = useQuery({ queryKey: ["read", "detail", "observations", detailPath], enabled: selection?.kind === "observations", queryFn: ({ signal }) => readClient.getInventoryDraftObservation(detailPath!, { signal }) });
  const detail = selection?.kind === "nodes" ? nodeDetail : selection?.kind === "aliases" ? aliasDetail : observationDetail;
  if (records.draft.isPending) return <ReadViewState kind="loading" title="Loading Nodes" description="Finding the newest authorized inventory draft." />;
  if (records.draft.error) return <ReadViewState kind="denied" title="Nodes unavailable" description="The newest inventory draft could not be read in this scope." onRetry={() => void records.draft.refetch()} />;
  if (!records.reference) return <ReadViewState kind="empty" title="No inventory draft" description="Import and qualification actions are not available in this read-only Console." />;
  const draft = records.draft.data!.data.items[0]!;
  return <div className="space-y-5"><Card><CardHeader><CardTitle>Draft inventory</CardTitle></CardHeader><CardContent className="space-y-2"><p>Revision {draft.revision} · {draft.validationStatus} · declared authority</p><p className="text-sm text-muted-foreground">Qualification is unavailable until its owning phase supplies verified records.</p>{records.source.data?.data.items[0] ? <SourceStatus source={records.source.data.data.items[0]} /> : <p className="text-sm">Node source status is unknown.</p>}</CardContent></Card><RecordSection kind="nodes" title="Nodes" items={records.collections.nodes.data?.data.items ?? []} next={records.collections.nodes.data?.data.nextCursor ?? null} back={records.pages.nodes.back.length > 0} busy={records.collections.nodes.isFetching} move={records.move} select={(kind, id, element) => { trigger.current = element; setSelection({ kind, id }); }} /><RecordSection kind="aliases" title="Aliases" items={records.collections.aliases.data?.data.items ?? []} next={records.collections.aliases.data?.data.nextCursor ?? null} back={records.pages.aliases.back.length > 0} busy={records.collections.aliases.isFetching} move={records.move} select={(kind, id, element) => { trigger.current = element; setSelection({ kind, id }); }} /><RecordSection kind="observations" title="Observations" items={records.collections.observations.data?.data.items ?? []} next={records.collections.observations.data?.data.nextCursor ?? null} back={records.pages.observations.back.length > 0} busy={records.collections.observations.isFetching} move={records.move} select={(kind, id, element) => { trigger.current = element; setSelection({ kind, id }); }} /><ReadDetail title={selection ? `${selection.kind.slice(0, -1)} details` : "Record details"} open={Boolean(selection)} onOpenChange={open => !open && setSelection(null)} returnFocusRef={trigger}>{detail.isPending ? <p role="status">Loading authorized details…</p> : detail.error ? <p role="alert">Record details are unavailable for this scope.</p> : <dl className="grid gap-2">{detail.data ? Object.entries(detail.data.data).map(([key, value]) => <div key={key}><dt className="text-sm font-medium">{key}</dt><dd className="break-words text-sm text-muted-foreground">{value === null ? "Not available" : String(value)}</dd></div>) : null}</dl>}</ReadDetail></div>;
}

function RecordSection({ kind, title, items, next, back, busy, move, select }: { kind: Kind; title: string; items: readonly { id: string }[]; next: string | null; back: boolean; busy: boolean; move: (kind: Kind, next: string | null | "back") => void; select: (kind: Kind, id: string, element: HTMLButtonElement) => void }) {
  return <section aria-labelledby={`${kind}-heading`} className="space-y-3"><h2 id={`${kind}-heading`} className="text-lg font-semibold">{title}</h2>{busy && items.length === 0 ? <ReadViewState kind="loading" title={`Loading ${title}`} description="Reading an authorized server page." /> : items.length === 0 ? <ReadViewState kind="empty" title={`No ${title.toLowerCase()}`} description="This draft contains no authorized records in this collection." /> : <div className="grid gap-2 sm:grid-cols-2">{items.map(item => <Card key={item.id} size="sm"><CardContent className="flex items-center justify-between gap-3"><span className="min-w-0 truncate">{item.id}</span><Button className="min-h-11" variant="outline" onClick={event => select(kind, item.id, event.currentTarget)}>View {kind.slice(0, -1)}</Button></CardContent></Card>)}</div>}<ReadPagination label={title} hasPrevious={back} hasNext={Boolean(next)} busy={busy} onPrevious={() => move(kind, "back")} onNext={() => move(kind, next)} /></section>;
}

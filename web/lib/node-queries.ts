"use client";

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import type { ApiPageQuery } from "@/generated/read-api";
import { readClient } from "@/lib/read-client";
import { readKeys, readQueries } from "@/lib/read-queries";

type Collection = "nodes" | "aliases" | "observations";
type CursorState = { current: string | null; back: readonly (string | null)[] };
const initialCursor: CursorState = { current: null, back: [] };

export function useNodeRecords() {
  const draft = useQuery(readQueries.drafts({ limit: 1, sort: "created-at-desc" }));
  const reference = draft.data?.data.items[0] ? { draftId: draft.data.data.items[0].draftId, revision: draft.data.data.items[0].revision } : undefined;
  const [pages, setPages] = useState<Record<Collection, CursorState>>({ nodes: initialCursor, aliases: initialCursor, observations: initialCursor });
  const page = (kind: Collection): ApiPageQuery => ({ limit: 25, sort: "id-asc", ...(pages[kind].current ? { cursor: pages[kind].current } : {}) });
  const nodes = useQuery({ queryKey: reference ? readKeys.nodes(reference, page("nodes")) : ["read", "nodes", "disabled"], enabled: Boolean(reference), queryFn: ({ signal }) => readClient.listInventoryDraftNodes(reference!, page("nodes"), { signal }) });
  const aliases = useQuery({ queryKey: reference ? readKeys.aliases(reference, page("aliases")) : ["read", "aliases", "disabled"], enabled: Boolean(reference), queryFn: ({ signal }) => readClient.listInventoryDraftAliases(reference!, page("aliases"), { signal }) });
  const observations = useQuery({ queryKey: reference ? readKeys.observations(reference, page("observations")) : ["read", "observations", "disabled"], enabled: Boolean(reference), queryFn: ({ signal }) => readClient.listInventoryDraftObservations(reference!, page("observations"), { signal }) });
  const source = useQuery(readQueries.sources({ limit: 1, source: "nodes" }));
  const move = (kind: Collection, next: string | null | "back") => setPages(current => {
    const selected = current[kind];
    if (next === "back") return { ...current, [kind]: { current: selected.back.at(-1) ?? null, back: selected.back.slice(0, -1) } };
    return { ...current, [kind]: { current: next, back: [...selected.back, selected.current] } };
  });
  return { draft, reference, source, collections: { nodes, aliases, observations }, pages, move };
}

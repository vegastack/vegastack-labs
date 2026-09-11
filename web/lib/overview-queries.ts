"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { classifyReadFailure, mayRetainStaleData, readQueries, readKeys } from "@/lib/read-queries";

export const overviewSourceIds = ["database", "nodes", "gates", "people", "services", "backups", "providers"] as const;

export function useOverview() {
  const queryClient = useQueryClient();
  const summary = useQuery(readQueries.summary());
  const sources = useQuery(readQueries.sources({ limit: 25, sort: "id-asc" }));
  const failures = [
    ...(summary.error ? [{ error: summary.error, retained: Boolean(summary.data) }] : []),
    ...(sources.error ? [{ error: sources.error, retained: Boolean(sources.data) }] : []),
  ];
  const failureStates = failures.map(failure => classifyReadFailure(failure.error, failure.retained));
  const sourceIds = new Set(sources.data?.data.items.map(source => source.id) ?? []);
  const missingSources = overviewSourceIds.some(id => !sourceIds.has(id));
  const empty = Boolean(summary.data && sources.data && summary.data.data.draftCount === 0 && sources.data.data.items.length === 0);
  const state = failureStates.includes("denied") ? "denied"
    : failureStates.includes("error") ? "error"
    : failureStates.includes("unavailable") ? (summary.data || sources.data ? "partial" : "unavailable")
    : failures.length > 0 && failures.every(failure => mayRetainStaleData(failure.error) && failure.retained) ? "stale"
    : failures.length > 0 ? "partial"
    : summary.isPending || sources.isPending ? "loading"
    : empty || (!summary.data && !sources.data) ? "empty"
    : missingSources ? "partial"
    : "success";
  const refresh = async () => {
    await queryClient.cancelQueries({ queryKey: ["read"] });
    await Promise.all([summary.refetch(), sources.refetch()]);
  };
  return { summary: summary.data?.data, sources: sources.data?.data.items ?? [], state, isRefreshing: summary.isFetching || sources.isFetching, refresh, keys: [readKeys.summary(), readKeys.sources({ limit: 25, sort: "id-asc" })] };
}

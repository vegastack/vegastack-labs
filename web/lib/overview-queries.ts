"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ReadClientError } from "@/generated/read-api";
import { mayRetainStaleData, readQueries, readKeys } from "@/lib/read-queries";

export function useOverview() {
  const queryClient = useQueryClient();
  const summary = useQuery(readQueries.summary());
  const sources = useQuery(readQueries.sources({ limit: 25, sort: "id-asc" }));
  const errors = [summary.error, sources.error].filter(Boolean);
  const denied = errors.some(error => error instanceof ReadClientError && ["AUTHENTICATION_REQUIRED", "AUTHORIZATION_DENIED", "SESSION_EXPIRED"].includes(error.code));
  const retryable = errors.some(mayRetainStaleData);
  const hasData = Boolean(summary.data || sources.data);
  const state = denied ? "denied" : errors.length > 0 && retryable && hasData ? "stale" : errors.length === 1 && hasData ? "partial" : errors.length > 0 ? "error" : summary.isPending || sources.isPending ? "loading" : !summary.data && !sources.data ? "empty" : "success";
  const refresh = async () => {
    await queryClient.cancelQueries({ queryKey: ["read"] });
    await Promise.all([summary.refetch(), sources.refetch()]);
  };
  return { summary: summary.data?.data, sources: sources.data?.data.items ?? [], state, isRefreshing: summary.isFetching || sources.isFetching, refresh, keys: [readKeys.summary(), readKeys.sources({ limit: 25, sort: "id-asc" })] };
}

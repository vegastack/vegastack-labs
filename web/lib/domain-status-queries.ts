"use client";

import { useQuery } from "@tanstack/react-query";
import { ReadClientError, type ApiSourceData } from "@/generated/read-api";
import { readClient } from "@/lib/read-client";
import { classifyReadFailure, type ReadFailureState } from "@/lib/read-queries";

export type DomainSource = Extract<ApiSourceData["id"], "people" | "services" | "backups" | "providers">;
export type DomainCapability = Extract<ApiSourceData["capability"], "identity.person.read" | "service.read" | "backup.status.read" | "adapter.status.read">;

export interface DomainStatusDefinition {
  source: DomainSource;
  capability: DomainCapability;
  title: string;
  unavailableDescription: string;
  currentDescription: string;
}

export type DomainStatusState = "loading" | "current" | "unknown" | "stale" | "unavailable" | "error" | "denied";

export function useDomainStatus(definition: DomainStatusDefinition): { source: ApiSourceData | undefined; state: DomainStatusState; isRefreshing: boolean; refresh: () => void } {
  const query = useQuery({
    queryKey: ["read", "sources", { limit: 1, source: definition.source }],
    queryFn: async ({ signal }) => {
      const result = await readClient.listSources({ limit: 1, source: definition.source }, { signal });
      const source = result.data.items[0];
      if (result.data.items.length > 1 || (source && (source.id !== definition.source || source.capability !== definition.capability))) {
        throw new ReadClientError("schema-mismatch", "INTEGRITY_FAILURE", "domain source response");
      }
      return result;
    },
  });
  const source = query.data?.data.items[0];
  let state: DomainStatusState;
  if (query.isPending) state = "loading";
  else if (query.error) state = classifyReadFailure(query.error, Boolean(query.data)) as ReadFailureState;
  else if (!source) state = "unknown";
  else state = source.state === "healthy" ? "current" : source.state === "failed" ? "error" : source.state;
  return { source, state, isRefreshing: query.isFetching, refresh: () => void query.refetch() };
}

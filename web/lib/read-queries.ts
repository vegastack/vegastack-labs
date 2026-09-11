import { ReadClientError, type ApiPageQuery, type ApiSourceListQuery } from "@/generated/read-api";
import { readClient } from "@/lib/read-client";

export const readKeys = {
  summary: () => ["read", "summary"] as const,
  sources: (query: ApiSourceListQuery = {}) => ["read", "sources", query] as const,
  drafts: (query: ApiPageQuery = {}) => ["read", "drafts", query] as const,
  nodes: (reference: { draftId: string; revision: number }, query: ApiPageQuery = {}) => ["read", "nodes", reference, query] as const,
  aliases: (reference: { draftId: string; revision: number }, query: ApiPageQuery = {}) => ["read", "aliases", reference, query] as const,
  observations: (reference: { draftId: string; revision: number }, query: ApiPageQuery = {}) => ["read", "observations", reference, query] as const,
};

export function isHardReadFailure(error: unknown): boolean {
  return error instanceof ReadClientError && (
    error.code === "AUTHENTICATION_REQUIRED" || error.code === "AUTHORIZATION_DENIED" ||
    error.code === "SESSION_EXPIRED" || error.code === "INTEGRITY_FAILURE" ||
    error.code === "SCHEMA_UNSUPPORTED"
  );
}

export function mayRetainStaleData(error: unknown): boolean {
  return error instanceof ReadClientError && error.code === "DEPENDENCY_UNAVAILABLE" && error.retryable;
}

export const readQueries = {
  summary: () => ({ queryKey: readKeys.summary(), queryFn: ({ signal }: { signal: AbortSignal }) => readClient.getSummary({ signal }) }),
  sources: (query: ApiSourceListQuery = {}) => ({ queryKey: readKeys.sources(query), queryFn: ({ signal }: { signal: AbortSignal }) => readClient.listSources(query, { signal }) }),
  drafts: (query: ApiPageQuery = {}) => ({ queryKey: readKeys.drafts(query), queryFn: ({ signal }: { signal: AbortSignal }) => readClient.listInventoryDrafts(query, { signal }) }),
  nodes: (reference: { draftId: string; revision: number }, query: ApiPageQuery = {}) => ({ queryKey: readKeys.nodes(reference, query), queryFn: ({ signal }: { signal: AbortSignal }) => readClient.listInventoryDraftNodes(reference, query, { signal }) }),
  aliases: (reference: { draftId: string; revision: number }, query: ApiPageQuery = {}) => ({ queryKey: readKeys.aliases(reference, query), queryFn: ({ signal }: { signal: AbortSignal }) => readClient.listInventoryDraftAliases(reference, query, { signal }) }),
  observations: (reference: { draftId: string; revision: number }, query: ApiPageQuery = {}) => ({ queryKey: readKeys.observations(reference, query), queryFn: ({ signal }: { signal: AbortSignal }) => readClient.listInventoryDraftObservations(reference, query, { signal }) }),
};

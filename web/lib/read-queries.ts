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

const deniedCodes = new Set(["AUTHENTICATION_REQUIRED", "AUTHORIZATION_DENIED", "SESSION_EXPIRED"]);

export type ReadFailureState = "stale" | "denied" | "unavailable" | "error";

export function isHardReadFailure(error: unknown): boolean {
  return !mayRetainStaleData(error);
}

export function mayRetainStaleData(error: unknown): boolean {
  return error instanceof ReadClientError && error.code === "DEPENDENCY_UNAVAILABLE" && error.retryable;
}

export function classifyReadFailure(error: unknown, hasRetainedData = false): ReadFailureState {
  if (mayRetainStaleData(error) && hasRetainedData) return "stale";
  if (error instanceof ReadClientError && deniedCodes.has(error.code)) return "denied";
  if (error instanceof ReadClientError && (error.kind === "network" || error.code === "DEPENDENCY_UNAVAILABLE" || error.code === "TARGET_UNREACHABLE")) return "unavailable";
  return "error";
}

export const readQueries = {
  summary: () => ({ queryKey: readKeys.summary(), queryFn: ({ signal }: { signal: AbortSignal }) => readClient.getSummary({ signal }) }),
  sources: (query: ApiSourceListQuery = {}) => ({ queryKey: readKeys.sources(query), queryFn: ({ signal }: { signal: AbortSignal }) => readClient.listSources(query, { signal }) }),
  drafts: (query: ApiPageQuery = {}) => ({ queryKey: readKeys.drafts(query), queryFn: ({ signal }: { signal: AbortSignal }) => readClient.listInventoryDrafts(query, { signal }) }),
  nodes: (reference: { draftId: string; revision: number }, query: ApiPageQuery = {}) => ({ queryKey: readKeys.nodes(reference, query), queryFn: ({ signal }: { signal: AbortSignal }) => readClient.listInventoryDraftNodes(reference, query, { signal }) }),
  aliases: (reference: { draftId: string; revision: number }, query: ApiPageQuery = {}) => ({ queryKey: readKeys.aliases(reference, query), queryFn: ({ signal }: { signal: AbortSignal }) => readClient.listInventoryDraftAliases(reference, query, { signal }) }),
  observations: (reference: { draftId: string; revision: number }, query: ApiPageQuery = {}) => ({ queryKey: readKeys.observations(reference, query), queryFn: ({ signal }: { signal: AbortSignal }) => readClient.listInventoryDraftObservations(reference, query, { signal }) }),
};

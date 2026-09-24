"use client";

import { MutationCache, QueryCache, QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createContext, useContext, useMemo, useState, type ReactNode } from "react";
import { ReadClientError } from "@/generated/read-api";
import { isHardReadFailure } from "@/lib/read-queries";

type FailureScope = "all" | "inventory" | "overview" | "gates" | "changes" | "phase5" | `source:${string}`;
type FailureNotice = { error: unknown; scope: FailureScope } | null;
const FailureContext = createContext<{ notice: FailureNotice; clear: () => void }>({ notice: null, clear: () => undefined });

function isInventoryKey(key: readonly unknown[]): boolean {
  return key[0] === "read" && ["drafts", "nodes", "aliases", "observations", "detail"].includes(String(key[1]));
}

function keyScope(key: readonly unknown[]): Exclude<FailureScope, "all"> {
  if ((key[0] === "read" || key[0] === "change") && key[1] === "phase5") return "phase5";
  if (key[0] === "change") return "changes";
  if (isInventoryKey(key)) return "inventory";
  if (key[0] === "read" && key[1] === "sources") {
    const source = (key[2] as { source?: string } | undefined)?.source;
    if (source === "nodes") return "inventory";
    if (source === "gates") return "gates";
    if (source) return `source:${source}`;
  }
  return "overview";
}

const stateClearingCodes = new Set([
  "AUTHENTICATION_REQUIRED",
  "AUTHORIZATION_DENIED",
  "INTEGRITY_FAILURE",
  "PLAN_STALE",
  "RECOVERY_EPOCH_MISMATCH",
  "RESOURCE_NOT_FOUND",
  "SCHEMA_UNSUPPORTED",
  "SESSION_EXPIRED",
  "STATE_CONFLICT",
  "VERSION_INCOMPATIBLE",
]);

function mustClearMountedState(error: unknown): boolean {
  if (error instanceof Error && error.name === "AbortError") return false;
  if (!(error instanceof ReadClientError)) return false;
  return stateClearingCodes.has(error.code) || error.kind === "malformed-json" || error.kind === "schema-mismatch" || error.kind === "unsupported-version";
}

export function useReadFailure(scope: FailureScope) {
  const context = useContext(FailureContext);
  return { failure: context.notice && (context.notice.scope === "all" || context.notice.scope === scope) ? context.notice.error : null, clearFailure: context.clear };
}

export function ConsoleQueryProvider({ children }: { children: ReactNode }) {
  const [notice, setNotice] = useState<FailureNotice>(null);
  const [client] = useState(() => {
    function clearOperationalData(error: unknown, key: readonly unknown[]) {
      if (!mustClearMountedState(error)) return;
      const global = error instanceof ReadClientError && ["AUTHENTICATION_REQUIRED", "SESSION_EXPIRED"].includes(error.code);
      const scope: FailureScope = global ? "all" : keyScope(key);
      setNotice({ error, scope });
      for (const cached of queryCache.findAll()) {
        if (cached.queryKey[0] !== "read" && cached.queryKey[0] !== "change") continue;
        if (scope === "all" || keyScope(cached.queryKey) === scope) cached.setState({ data: null });
      }
    }
    const queryCache = new QueryCache({
      onError: (error, query) => {
        if (!isHardReadFailure(error)) return;
        clearOperationalData(error, query.queryKey);
        if (!mustClearMountedState(error)) query.setState({ data: null });
      },
    });
    const mutationCache = new MutationCache({
      onError: (error, _variables, _result, mutation) => {
        const key = mutation.options.mutationKey ?? ["change"];
        clearOperationalData(error, key);
      },
    });
    return new QueryClient({
      queryCache,
      mutationCache,
      defaultOptions: {
        queries: {
          retry: false,
          gcTime: 0,
          staleTime: 0,
          refetchOnMount: false,
          retryOnMount: false,
          refetchOnReconnect: false,
          refetchOnWindowFocus: false,
        },
      },
    });
  });
  const failure = useMemo(() => ({ notice, clear: () => setNotice(null) }), [notice]);
  return <FailureContext.Provider value={failure}><QueryClientProvider client={client}>{children}</QueryClientProvider></FailureContext.Provider>;
}

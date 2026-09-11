"use client";

import { QueryCache, QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createContext, useContext, useMemo, useState, type ReactNode } from "react";
import { ReadClientError } from "@/generated/read-api";
import { isHardReadFailure } from "@/lib/read-queries";

type FailureScope = "all" | "inventory" | "overview" | "gates" | `source:${string}`;
type FailureNotice = { error: unknown; scope: FailureScope } | null;
const FailureContext = createContext<{ notice: FailureNotice; clear: () => void }>({ notice: null, clear: () => undefined });

function isInventoryKey(key: readonly unknown[]): boolean {
  return key[0] === "read" && ["drafts", "nodes", "aliases", "observations", "detail"].includes(String(key[1]));
}

function keyScope(key: readonly unknown[]): Exclude<FailureScope, "all"> {
  if (isInventoryKey(key)) return "inventory";
  if (key[0] === "read" && key[1] === "sources") {
    const source = (key[2] as { source?: string } | undefined)?.source;
    if (source === "nodes") return "inventory";
    if (source === "gates") return "gates";
    if (source) return `source:${source}`;
  }
  return "overview";
}

export function useReadFailure(scope: FailureScope) {
  const context = useContext(FailureContext);
  return { failure: context.notice && (context.notice.scope === "all" || context.notice.scope === scope) ? context.notice.error : null, clearFailure: context.clear };
}

export function ConsoleQueryProvider({ children }: { children: ReactNode }) {
  const [notice, setNotice] = useState<FailureNotice>(null);
  const [client] = useState(() => {
    const queryCache = new QueryCache({
      onError: (error, query) => {
        if (!isHardReadFailure(error)) return;
        const global = error instanceof ReadClientError && ["AUTHENTICATION_REQUIRED", "SESSION_EXPIRED"].includes(error.code);
        const authorizationDenial = error instanceof ReadClientError && error.code === "AUTHORIZATION_DENIED";
        const scope: FailureScope = global ? "all" : keyScope(query.queryKey);
        if (global || authorizationDenial) {
          setNotice({ error, scope });
          for (const cached of queryCache.findAll({ queryKey: ["read"] })) {
            if (scope === "all" || keyScope(cached.queryKey) === scope) cached.setState({ data: null });
          }
        } else {
          query.setState({ data: null });
        }
      },
    });
    return new QueryClient({
      queryCache,
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

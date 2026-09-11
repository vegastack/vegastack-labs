"use client";

import { QueryCache, QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState, type ReactNode } from "react";
import { isHardReadFailure } from "@/lib/read-queries";

export function ConsoleQueryProvider({ children }: { children: ReactNode }) {
  const [client] = useState(() => {
    const queryCache = new QueryCache({
      onError: (error) => {
        if (!isHardReadFailure(error)) return;
        // A hard failure can represent a revoked shared grant or session. Clear
        // every operational read payload before React paints the failure so a
        // sibling query cannot leave records from the old scope visible.
        for (const cached of queryCache.findAll({ queryKey: ["read"] })) cached.setState({ data: null });
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
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

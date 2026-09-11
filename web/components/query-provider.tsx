"use client";

import { QueryCache, QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState, type ReactNode } from "react";
import { isHardReadFailure } from "@/lib/read-queries";

export function ConsoleQueryProvider({ children }: { children: ReactNode }) {
  const [client] = useState(() => {
    const queryCache = new QueryCache({
      onError: (error, query) => {
        if (isHardReadFailure(error)) queryCache.remove(query);
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
          refetchOnReconnect: false,
          refetchOnWindowFocus: false,
        },
      },
    });
  });
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

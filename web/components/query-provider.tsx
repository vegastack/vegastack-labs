"use client";

import { QueryCache, QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState, type ReactNode } from "react";
import { isHardReadFailure } from "@/lib/read-queries";

export function ConsoleQueryProvider({ children }: { children: ReactNode }) {
  const [client] = useState(() => {
    const queryCache = new QueryCache({
      onError: (error, query) => {
        // Keep the error state while replacing any prior authorized payload.
        // Views treat null as no readable data and render the hard failure.
        if (isHardReadFailure(error)) query.setState({ data: null });
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

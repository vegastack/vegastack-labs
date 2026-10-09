"use client";

import { useMutation, useQuery } from "@tanstack/react-query";
import { ReadClientError, type HostReplacementRequest } from "@/generated/read-api";
import { hostClient } from "@/lib/host-lifecycle-queries";

export function useHostReplacementDraft() {
  return useMutation({ mutationKey: ["change", "hosts", "replacement"], retry: false,
    mutationFn: (request: HostReplacementRequest) => hostClient.prepareHostReplacement(request) });
}
export function useHostReplacement(id: string | null) {
  return useQuery({ queryKey: ["read", "hosts", "replacement", id], enabled: Boolean(id), retry: false,
    queryFn: async ({ signal }) => {
      const result = await hostClient.getHostReplacement({ replacementId: id! }, { signal });
      if (result.data.replacementId !== id) throw new ReadClientError("schema-mismatch", "INTEGRITY_FAILURE", "host-replacement");
      return result;
    } });
}

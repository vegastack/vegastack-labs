"use client";
import type {
  ReadResult,
  OperatorDeviceList,
  OperatorGrantList,
} from "@/generated/read-api";
import { useQuery } from "@tanstack/react-query";
import { readClient } from "@/lib/read-client";
import { classifyReadFailure } from "@/lib/read-queries";
import { useReadFailure } from "@/components/query-provider";
export const operatorAccessKey = ["read", "operator-access"] as const;
export function usePeople(after: string) {
  const { failure, clearFailure } = useReadFailure("operator-access");
  const query = useQuery({
    queryKey: [...operatorAccessKey, "people", after],
    queryFn: ({ signal }) =>
      readClient.listPeople(
        { ...(after ? { after } : {}), limit: 100 },
        { signal },
      ),
  });
  const error = query.error ?? failure;
  return {
    ...query,
    state: error
      ? classifyReadFailure(error, Boolean(query.data))
      : query.isPending
        ? "loading"
        : "current",
    refresh: () => {
      clearFailure();
      void query.refetch();
    },
  };
}
export function usePersonAccess(
  principalId: string,
  kind: "devices" | "grants",
  after: string,
) {
  const { failure, clearFailure } = useReadFailure("operator-access");
  const query = useQuery<ReadResult<OperatorDeviceList | OperatorGrantList>>({
    queryKey: [...operatorAccessKey, kind, principalId, after],
    queryFn: ({ signal }) =>
      kind === "devices"
        ? readClient.listDevices(
            { principalId, ...(after ? { after } : {}), limit: 100 },
            { signal },
          )
        : readClient.listGrants(
            { principalId, ...(after ? { after } : {}), limit: 100 },
            { signal },
          ),
  });
  const error = query.error ?? failure;
  return {
    ...query,
    state: error
      ? classifyReadFailure(error, Boolean(query.data))
      : query.isPending
        ? "loading"
        : "current",
    refresh: () => {
      clearFailure();
      void query.refetch();
    },
  };
}

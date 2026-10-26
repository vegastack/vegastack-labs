"use client";

import { useQuery, useQueryClient, type UseQueryResult } from "@tanstack/react-query";
import { useReadFailure } from "@/components/query-provider";
import { readClient } from "@/lib/read-client";
import { classifyReadFailure } from "@/lib/read-queries";

export const serviceKey = ["read", "services"] as const;

function useServiceState<T>(query: UseQueryResult<T, Error>) {
  const { failure, clearFailure } = useReadFailure("services");
  const error = failure ?? query.error;
  return {
    ...query,
    state: error ? classifyReadFailure(error, Boolean(query.data)) : query.isPending ? "loading" as const : "current" as const,
    refresh: () => { clearFailure(); void query.refetch(); },
  };
}

export function useServices(after: string) {
  const client = useQueryClient();
  const { clearFailure } = useReadFailure("services");
  const query = useServiceState(useQuery({
    queryKey: [...serviceKey, "list", after],
    queryFn: ({ signal }) => readClient.listServices({ ...(after ? { after } : {}), limit: 25 }, { signal }),
  }));
  return { ...query, refresh: () => { clearFailure(); void client.refetchQueries({ queryKey: serviceKey, type: "active" }); } };
}

export function useService(serviceId: string) {
  return useServiceState(useQuery({
    queryKey: [...serviceKey, "detail", serviceId],
    queryFn: ({ signal }) => readClient.getService({ serviceID: serviceId }, { signal }),
  }));
}

export function useServiceObservation(serviceId: string) {
  return useServiceState(useQuery({
    queryKey: [...serviceKey, "observation", serviceId],
    queryFn: ({ signal }) => readClient.getServiceObservation({ serviceID: serviceId }, { signal }),
  }));
}

export function useServiceConfiguration(serviceId: string) {
  return useServiceState(useQuery({
    queryKey: [...serviceKey, "configuration", serviceId],
    queryFn: ({ signal }) => readClient.getServiceConfiguration({ serviceID: serviceId }, { signal }),
  }));
}

export function useServiceDeployment(serviceId: string) {
  return useServiceState(useQuery({
    queryKey: [...serviceKey, "deployment", serviceId],
    queryFn: ({ signal }) => readClient.getServiceDeployment({ serviceID: serviceId }, { signal }),
  }));
}

export function useServiceRecovery(serviceId: string) {
  return useServiceState(useQuery({
    queryKey: [...serviceKey, "recovery", serviceId],
    queryFn: ({ signal }) => readClient.getServiceRecovery({ serviceID: serviceId }, { signal }),
  }));
}

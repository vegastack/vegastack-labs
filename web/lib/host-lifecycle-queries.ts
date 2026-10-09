"use client";

import { useMutation, useQuery } from "@tanstack/react-query";
import { createHostClient, ReadClientError, type HostDiscoveryTargetDraftRequest, type HostAdoptionRequest, type HostDiscoveryRequest, type HostActionRequest, type HostAccessDraftRequest } from "@/generated/read-api";
import { changeClient, readClient } from "@/lib/read-client";
import { planFromView } from "@/lib/change-queries";

export const hostClient = createHostClient((input, init) => fetch(input, init));
export const hostKeys = {
  host: (id: string | null) => ["read", "hosts", "host", id] as const,
  observation: (id: string | null) => ["read", "hosts", "observation", id] as const,
};
export function useManagedHost(id: string | null) {
  return useQuery({ queryKey: hostKeys.host(id), enabled: Boolean(id), queryFn: ({ signal }) => hostClient.getHosts({ hostID: id! }, { signal }), retry: false });
}
export function useHostObservation(id: string | null) {
  return useQuery({ queryKey: hostKeys.observation(id), enabled: Boolean(id), queryFn: ({ signal }) => hostClient.getHostObservation({ observationID: id! }, { signal }), retry: false });
}
export function useHostTargetDraft() { return useMutation({ mutationKey: ["change", "hosts", "target"], retry: false, mutationFn: (input: HostDiscoveryTargetDraftRequest) => hostClient.prepareHostTarget(input) }); }
export function useHostDiscovery() { return useMutation({ mutationKey: ["change", "hosts", "discover"], retry: false, mutationFn: (input: HostDiscoveryRequest) => hostClient.discoverHost(input) }); }
export function useHostAdoption() { return useMutation({ mutationKey: ["change", "hosts", "adoption"], retry: false, mutationFn: (input: HostAdoptionRequest) => hostClient.prepareHostAdoption(input) }); }
export function useHostActionDraft() { return useMutation({ mutationKey: ["change", "hosts", "action"], retry: false, mutationFn: (input: HostActionRequest) => hostClient.prepareHostAction(input) }); }
export function useHostAccessDraft() { return useMutation({ mutationKey: ["change", "hosts", "access"], retry: false, mutationFn: (input: HostAccessDraftRequest) => hostClient.prepareHostAccess(input) }); }
export function useHostPlan() {
  return useMutation({ mutationKey: ["change", "hosts", "plan"], retry: false, mutationFn: async (declarationId: string) => {
    const prepared = await changeClient.preparePlan({ declarationId, revision: 1 });
    const p = prepared.data;
    if (p.declarationId !== declarationId || p.declarationRevision !== 1 || p.recoveryEpoch !== prepared.recoveryEpoch || p.expectedStateRevision !== prepared.stateRevision) throw new ReadClientError("schema-mismatch", "INTEGRITY_FAILURE", "host-plan-preparation");
    const result = await changeClient.createPlan({ declarationId }, { schema: "vegastack-labs.dev/plan-create-request", schemaVersion: "1.0.0", declarationId, declarationRevision: p.declarationRevision, expectedStateRevision: p.expectedStateRevision, recoveryEpoch: p.recoveryEpoch, observationFingerprint: p.observationFingerprint, idempotencyKey: `console-host-plan-${crypto.randomUUID()}`, extensions: [] });
    const plan = planFromView(result.data);
    if (plan.declarationId !== declarationId || plan.binding.declarationRevision !== p.declarationRevision + 1 || plan.binding.recoveryEpoch !== p.recoveryEpoch || result.recoveryEpoch !== p.recoveryEpoch || plan.binding.priorStateRevision !== p.expectedStateRevision || plan.binding.stateRevision !== result.stateRevision || plan.binding.observationFingerprint !== p.observationFingerprint) throw new ReadClientError("schema-mismatch", "INTEGRITY_FAILURE", "host-plan");
    return plan;
  } });
}

export function useHostAdmission(id: string, gateId: "host.hardening-baseline" | "host.role-admission", revision: number, epoch: number) {
  return useQuery({ queryKey: ["read", "hosts", "admission", id, gateId, revision, epoch], retry: false,
    queryFn: async ({ signal }) => {
      const result = await readClient.getGate({ gateId }, { subjectId: id }, { signal });
      if (result.data.evaluation.subjectId !== id || result.data.evaluation.gateId !== gateId || result.data.definition.gateId !== gateId || result.data.evaluation.recoveryEpoch !== result.recoveryEpoch) throw new ReadClientError("schema-mismatch", "INTEGRITY_FAILURE", "host-admission");
      return result;
    },
  });
}

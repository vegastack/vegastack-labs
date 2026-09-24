"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import type { ApiPageQuery, BrowserRestoreDraftRequest, GateCheckRequest, GateEvidenceRequest } from "@/generated/read-api";
import { phase5Client } from "@/lib/read-client";

const fixedReadOptions = {
  retry: false,
  refetchOnMount: false,
  retryOnMount: false,
  refetchOnReconnect: false,
  refetchOnWindowFocus: false,
} as const;

export const phase5Keys = {
  all: ["read", "phase5"] as const,
  backupStatus: () => ["read", "phase5", "backup-status"] as const,
  recoveryPoints: (query: ApiPageQuery = {}) => ["read", "phase5", "recovery-points", query] as const,
  auditCheckpoints: (query: ApiPageQuery = {}) => ["read", "phase5", "audit-checkpoints", query] as const,
  auditVerification: () => ["read", "phase5", "audit-verification"] as const,
  restoreStatuses: (query: ApiPageQuery = {}) => ["read", "phase5", "restore-statuses", query] as const,
  scheduledPolicies: (query: ApiPageQuery = {}) => ["read", "phase5", "scheduled-policies", query] as const,
  scheduledJobs: (query: ApiPageQuery = {}) => ["read", "phase5", "scheduled-jobs", query] as const,
};

export const phase5Queries = {
  backupStatus: () => ({ ...fixedReadOptions, queryKey: phase5Keys.backupStatus(), queryFn: ({ signal }: { signal: AbortSignal }) => phase5Client.getBackupStatus({ signal }) }),
  recoveryPoints: (query: ApiPageQuery = {}) => ({ ...fixedReadOptions, queryKey: phase5Keys.recoveryPoints(query), queryFn: ({ signal }: { signal: AbortSignal }) => phase5Client.listRecoveryPoints(query, { signal }) }),
  auditCheckpoints: (query: ApiPageQuery = {}) => ({ ...fixedReadOptions, queryKey: phase5Keys.auditCheckpoints(query), queryFn: ({ signal }: { signal: AbortSignal }) => phase5Client.listAuditCheckpoints(query, { signal }) }),
  auditVerification: () => ({ ...fixedReadOptions, queryKey: phase5Keys.auditVerification(), queryFn: ({ signal }: { signal: AbortSignal }) => phase5Client.getAuditVerification({ signal }) }),
  restoreStatuses: (query: ApiPageQuery = {}) => ({ ...fixedReadOptions, queryKey: phase5Keys.restoreStatuses(query), queryFn: ({ signal }: { signal: AbortSignal }) => phase5Client.listRestoreStatuses(query, { signal }) }),
  scheduledPolicies: (query: ApiPageQuery = {}) => ({ ...fixedReadOptions, queryKey: phase5Keys.scheduledPolicies(query), queryFn: ({ signal }: { signal: AbortSignal }) => phase5Client.listScheduledJobPolicies(query, { signal }) }),
  scheduledJobs: (query: ApiPageQuery = {}) => ({ ...fixedReadOptions, queryKey: phase5Keys.scheduledJobs(query), queryFn: ({ signal }: { signal: AbortSignal }) => phase5Client.listScheduledJobs(query, { signal }) }),
};

export function useCheckGate() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationKey: ["change", "phase5", "check-gate"],
    mutationFn: ({ gateId, request }: { gateId: string; request: GateCheckRequest }) => phase5Client.checkGate({ gateId }, request),
    onSuccess: async () => queryClient.invalidateQueries({ queryKey: ["read", "gates"] }),
  });
}

export function useDraftGateEvidence() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationKey: ["change", "phase5", "draft-gate-evidence"],
    mutationFn: ({ gateId, request }: { gateId: string; request: GateEvidenceRequest }) => phase5Client.draftGateEvidence({ gateId }, request),
    onSuccess: async () => queryClient.invalidateQueries({ queryKey: ["read", "gates"] }),
  });
}

export function useDraftRestore() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationKey: ["change", "phase5", "draft-restore"],
    mutationFn: ({ pointId, request }: { pointId: string; request: BrowserRestoreDraftRequest }) => phase5Client.draftRestore({ pointId }, request),
    onSuccess: async () => queryClient.invalidateQueries({ queryKey: phase5Keys.restoreStatuses() }),
  });
}

"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  type DeclarationRevisionRequest,
  type Plan,
  type PlanCreateRequest,
  type PlanReferenceRequest,
} from "@/generated/read-api";
import { changeClient } from "@/lib/read-client";

export { changeClient };
export type BrowserDeclaration = Awaited<ReturnType<typeof changeClient.getDeclaration>>["data"];
export type PlanView = Awaited<ReturnType<typeof changeClient.getPlan>>["data"];

export function planFromView(view: PlanView): Plan {
  return "plan" in view ? (view as PlanView & { readonly plan: Plan }).plan : view as Plan;
}

export const changeKeys = {
  all: ["change"] as const,
  declaration: (declarationId: string, revision: number) => ["change", "declaration", declarationId, revision] as const,
  plan: (planId: string) => ["change", "plan", planId] as const,
  approval: (planId: string) => ["change", "approval", planId] as const,
};

function actionKey(action: string): string {
  return `console-${action}-${crypto.randomUUID()}`;
}

export function useDeclaration(reference: { declarationId: string; revision: number } | null) {
  return useQuery({
    queryKey: reference ? changeKeys.declaration(reference.declarationId, reference.revision) : ["change", "declaration", "closed"],
    queryFn: ({ signal }) => changeClient.getDeclaration(reference!, { signal }),
    enabled: reference !== null,
  });
}

export function useSaveDeclaration() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationKey: ["change", "save-declaration"],
    mutationFn: (request: DeclarationRevisionRequest) => changeClient.reviseDeclaration({ declarationId: request.declarationId }, request),
    onSuccess: (result) => {
      queryClient.setQueryData(changeKeys.declaration(result.data.declarationId, result.data.revision), result);
      void queryClient.invalidateQueries({ queryKey: ["change", "declaration", result.data.declarationId] });
    },
  });
}

export function useCreatePlan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationKey: ["change", "create-plan"],
    mutationFn: async (declaration: BrowserDeclaration) => {
      const prepared = await changeClient.preparePlan({ declarationId: declaration.declarationId, revision: declaration.revision });
      const request: PlanCreateRequest = {
        schema: "vegastack-labs.dev/plan-create-request",
        schemaVersion: "1.0.0",
        declarationId: prepared.data.declarationId,
        declarationRevision: prepared.data.declarationRevision,
        expectedStateRevision: prepared.data.expectedStateRevision,
        recoveryEpoch: prepared.data.recoveryEpoch,
        observationFingerprint: prepared.data.observationFingerprint,
        idempotencyKey: actionKey("plan"),
        extensions: [],
      };
      return changeClient.createPlan({ declarationId: declaration.declarationId }, request);
    },
    onSuccess: (result) => {
      const plan = planFromView(result.data);
      queryClient.setQueryData(changeKeys.plan(plan.planId), result);
    },
  });
}

export function usePlan(planId: string | null) {
  return useQuery({
    queryKey: planId ? changeKeys.plan(planId) : ["change", "plan", "closed"],
    queryFn: ({ signal }) => changeClient.getPlan({ planId: planId! }, { signal }),
    enabled: planId !== null,
  });
}

export function useApprovalStatus(planId: string | null, enabled: boolean) {
  return useQuery({
    queryKey: planId ? changeKeys.approval(planId) : ["change", "approval", "closed"],
    queryFn: ({ signal }) => changeClient.getApprovalStatus({ planId: planId! }, { signal }),
    enabled: planId !== null && enabled,
    refetchInterval: 20_000,
    refetchOnWindowFocus: true,
  });
}

function planReference(plan: Plan, action: string): PlanReferenceRequest {
  return {
    schema: "vegastack-labs.dev/plan-reference-request",
    schemaVersion: "1.0.0",
    planId: plan.planId,
    planDigest: plan.planDigest,
    recoveryEpoch: plan.binding.recoveryEpoch,
    idempotencyKey: actionKey(action),
    extensions: [],
  };
}

export function useRequestApproval() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationKey: ["change", "request-approval"],
    mutationFn: (plan: Plan) => changeClient.requestApproval({ planId: plan.planId }, planReference(plan, "approval")),
    onSuccess: (result) => queryClient.setQueryData(changeKeys.approval(result.data.planId), result),
  });
}

export function useExecutePlan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationKey: ["change", "execute-plan"],
    mutationFn: (plan: Plan) => changeClient.executePlan({ planId: plan.planId }, planReference(plan, "run")),
    onSuccess: (result) => queryClient.setQueryData(["change", "run", result.data.run.runId], result),
    onError: (_error, plan) => {
      void queryClient.invalidateQueries({ queryKey: changeKeys.approval(plan.planId) });
    },
  });
}

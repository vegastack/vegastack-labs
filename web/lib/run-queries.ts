"use client";

import { useEffect, useRef } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type RunPresentation, type RunReferenceRequest } from "@/generated/read-api";
import { changeClient } from "@/lib/change-queries";
import { readClient } from "@/lib/read-client";

export const runKeys = {
  detail: (runId: string) => ["change", "run", runId] as const,
};

function runReference(run: RunPresentation["run"], action: string): RunReferenceRequest {
  return {
    schema: "vegastack-labs.dev/run-reference-request",
    schemaVersion: "1.0.0",
    runId: run.runId,
    idempotencyKey: `console-${action}-${crypto.randomUUID()}`,
    recoveryEpoch: run.recoveryEpoch,
    extensions: [],
  };
}

export function useRun(initial: RunPresentation | null) {
  const runId = initial?.run.runId ?? null;
  const query = useQuery({
    queryKey: runId ? runKeys.detail(runId) : ["change", "run", "closed"],
    queryFn: ({ signal }) => changeClient.getRun({ runId: runId! }, { signal }),
    enabled: runId !== null,
  });
  const refetch = query.refetch;
  const lastEventId = useRef<string | undefined>(undefined);
  useEffect(() => {
    if (!runId) return;
    const controller = new AbortController();
    const inspectDurableRun = () => { void refetch(); };
    globalThis.addEventListener("online", inspectDurableRun);
    void (async () => {
      try {
        for await (const update of readClient.streamEvents({ signal: controller.signal, lastEventId: lastEventId.current })) {
          lastEventId.current = String(update.event.eventId);
          if (update.event.target.kind === "run" && update.event.target.id === runId) await refetch();
        }
      } catch {
        if (!controller.signal.aborted) await refetch();
      }
    })();
    return () => { controller.abort(); globalThis.removeEventListener("online", inspectDurableRun); };
  }, [refetch, runId]);
  return query;
}

export function useCancelRun() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (presentation: RunPresentation) => changeClient.cancelRun({ runId: presentation.run.runId }, runReference(presentation.run, "cancel")),
    onSuccess: (result) => queryClient.setQueryData(runKeys.detail(result.data.run.runId), result),
  });
}

export function useResumeRun() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (presentation: RunPresentation) => changeClient.resumeRun({ runId: presentation.run.runId }, runReference(presentation.run, "resume")),
    onSuccess: (result) => queryClient.setQueryData(runKeys.detail(result.data.run.runId), result),
  });
}

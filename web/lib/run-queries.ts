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

const maximumReconnectDelay = 20_000;
const terminalRunStatuses = new Set(["cancelled", "failed", "interrupted", "partial", "succeeded"]);

async function waitForReconnect(attempt: number, signal: AbortSignal) {
  const delay = Math.min(500 * (2 ** Math.min(attempt, 5)), maximumReconnectDelay);
  await new Promise<void>((resolve) => {
    const timeout = globalThis.setTimeout(done, delay);
    function done() {
      globalThis.clearTimeout(timeout);
      signal.removeEventListener("abort", done);
      resolve();
    }
    signal.addEventListener("abort", done, { once: true });
  });
}

export function useRun(runId: string | null) {
  const query = useQuery({
    queryKey: runId ? runKeys.detail(runId) : ["change", "run", "closed"],
    queryFn: ({ signal }) => changeClient.getRun({ runId: runId! }, { signal }),
    enabled: runId !== null,
  });
  const refetch = query.refetch;
  const terminal = query.data ? terminalRunStatuses.has(query.data.data.run.status) : false;
  const lastEventId = useRef<string | undefined>(undefined);
  useEffect(() => {
    if (!runId || !query.data || terminal) return;
    const controller = new AbortController();
    lastEventId.current = undefined;
    const inspectDurableRun = () => { void refetch(); };
    globalThis.addEventListener("online", inspectDurableRun);
    void (async () => {
      let attempt = 0;
      while (!controller.signal.aborted) {
        await refetch();
        if (controller.signal.aborted) break;
        try {
          for await (const update of readClient.streamEvents({ signal: controller.signal, lastEventId: lastEventId.current })) {
            lastEventId.current = String(update.event.eventId);
            attempt = 0;
            if (update.event.target.kind === "run" && update.event.target.id === runId) await refetch();
          }
        } catch {
          if (controller.signal.aborted) break;
        }
        await refetch();
        if (controller.signal.aborted) break;
        await waitForReconnect(attempt, controller.signal);
        attempt += 1;
      }
    })();
    return () => { controller.abort(); globalThis.removeEventListener("online", inspectDurableRun); };
  }, [query.data, refetch, runId, terminal]);
  return query;
}

export function useCancelRun() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationKey: ["change", "cancel-run"],
    mutationFn: (presentation: RunPresentation) => changeClient.cancelRun({ runId: presentation.run.runId }, runReference(presentation.run, "cancel")),
    onSuccess: (result) => queryClient.setQueryData(runKeys.detail(result.data.run.runId), result),
  });
}

export function useResumeRun() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationKey: ["change", "resume-run"],
    mutationFn: (presentation: RunPresentation) => changeClient.resumeRun({ runId: presentation.run.runId }, runReference(presentation.run, "resume")),
    onSuccess: (result) => queryClient.setQueryData(runKeys.detail(result.data.run.runId), result),
  });
}

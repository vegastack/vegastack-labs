import type { ApiSourceData } from "@/generated/read-api";
import type { BadgeProps } from "@/components/ui/badge";
import type { StatusIconProps } from "@/components/ui/status-icon";

export type SourceState = ApiSourceData["state"];

type SourceDisplay = {
  label: string;
  intent: NonNullable<BadgeProps["intent"]>;
  status: NonNullable<StatusIconProps["status"]>;
};

/**
 * One canonical mapping from a control-plane source health state to its on-system
 * display roles, so every screen renders the same badge intent and status glyph
 * for the same state.
 */
export const sourceStateDisplay: Record<SourceState, SourceDisplay> = {
  healthy: { label: "Healthy", intent: "success", status: "done" },
  stale: { label: "Stale", intent: "warning", status: "progress" },
  unknown: { label: "Unknown", intent: "default", status: "todo" },
  unavailable: { label: "Unavailable", intent: "info", status: "todo" },
  failed: { label: "Failed", intent: "destructive", status: "blocked" },
};

export function sourceDisplay(state: SourceState): SourceDisplay {
  return sourceStateDisplay[state];
}

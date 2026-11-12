import { Badge } from "@/components/ui/badge";
import { StatusIcon } from "@/components/ui/status-icon";
import { sourceDisplay } from "@/lib/status-display";
import type { ApiSourceData } from "@/generated/read-api";

export function formatConsoleTime(value: string | null): string {
  if (!value) return "No collection time available";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Invalid collection time";
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone: "Asia/Kolkata",
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hour12: true,
  }).formatToParts(date);
  const part = (type: Intl.DateTimeFormatPartTypes) => parts.find((candidate) => candidate.type === type)?.value ?? "";
  return `${part("day")}-${part("month")}-${part("year")} ${part("hour")}:${part("minute")} ${part("dayPeriod").toUpperCase()} IST`;
}

/**
 * A compact, on-system rendering of one source's health, badge and freshness.
 * The freshness lines are contiguous "Label: value" text so status-freshness
 * assertions can match them exactly.
 */
export function SourceStatus({ source }: { source: ApiSourceData }) {
  const display = sourceDisplay(source.state);
  const label = { healthy: "Recent observation", stale: "Older observation", unknown: "Time not recorded", unavailable: "Not reported", failed: "Collection failed" }[source.state];
  const explanation = {
    healthy: "A recent observation is recorded for this source.",
    stale: "The saved observation is older than its freshness limit. This does not, by itself, mean the service is down.",
    unknown: "This summary has no observation time. Open the relevant page to inspect its available records.",
    unavailable: "This source is not reporting observations. Its page may still provide authorized records.",
    failed: "The source reported a collection failure. Inspect its page for the recorded reason and next action.",
  }[source.state];
  return (
    <div className="flex flex-col gap-2" data-source-state={source.state}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2">
          <StatusIcon status={display.status} size="sm" />
          <span className="min-w-0 truncate text-sm font-medium capitalize text-foreground">{source.id}</span>
        </div>
        <Badge intent={display.intent} size="md">
          {label}
        </Badge>
      </div>
      <p className="text-sm text-muted-foreground">{explanation}</p>
      {source.collectedAt ? <p className="text-xs text-muted-foreground">Recorded: {formatConsoleTime(source.collectedAt)}</p> : null}
      {source.lastSuccessAt && source.lastSuccessAt !== source.collectedAt ? <p className="text-xs text-muted-foreground">Last success: {formatConsoleTime(source.lastSuccessAt)}</p> : null}
      {source.lastErrorAt ? <p className="text-xs text-muted-foreground">Last recorded error: {formatConsoleTime(source.lastErrorAt)}</p> : null}
    </div>
  );
}

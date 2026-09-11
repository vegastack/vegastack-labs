import { Badge } from "@/components/ui/badge";
import type { ApiSourceData } from "@/generated/read-api";

const intent = { healthy: "success", stale: "warning", unknown: "default", unavailable: "info", failed: "destructive" } as const;

export function formatConsoleTime(value: string | null): string {
  if (!value) return "No collection time available";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Invalid collection time";
  const parts = new Intl.DateTimeFormat("en-US", { timeZone: "Asia/Kolkata", day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit", hour12: true }).formatToParts(date);
  const part = (type: Intl.DateTimeFormatPartTypes) => parts.find(candidate => candidate.type === type)?.value ?? "";
  return `${part("day")}-${part("month")}-${part("year")} ${part("hour")}:${part("minute")} ${part("dayPeriod").toUpperCase()} IST`;
}

export function SourceStatus({ source }: { source: ApiSourceData }) {
  return (
    <div className="space-y-2" data-source-state={source.state}>
      <div className="flex flex-wrap items-center justify-between gap-2"><span className="font-medium capitalize">{source.id}</span><Badge intent={intent[source.state]}>{source.state}</Badge></div>
      <p className="text-sm text-muted-foreground">{source.reason}</p>
      <p className="text-xs text-muted-foreground">Collected: {formatConsoleTime(source.collectedAt)}</p>
      <p className="text-xs text-muted-foreground">Last success: {formatConsoleTime(source.lastSuccessAt)}</p>
      <p className="text-xs text-muted-foreground">Last error: {formatConsoleTime(source.lastErrorAt)}</p>
    </div>
  );
}

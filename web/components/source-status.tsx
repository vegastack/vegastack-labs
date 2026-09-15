import { CalendarClock, CheckCircle2, TriangleAlert } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { StatusIcon } from "@/components/ui/status-icon";
import { PropertyList, PropertyLabel, PropertyRow, PropertyValue } from "@/components/ui/property-list";
import { sourceDisplay } from "@/lib/status-display";
import type { ApiSourceData } from "@/generated/read-api";

export function formatConsoleTime(value: string | null): string {
  if (!value) return "Not available";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Invalid time";
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

/** A compact, on-system rendering of one source's health, badge and freshness. */
export function SourceStatus({ source }: { source: ApiSourceData }) {
  const display = sourceDisplay(source.state);
  const times: Array<{ label: string; value: string | null; icon: React.ReactNode }> = [
    { label: "Collected", value: source.collectedAt, icon: <CalendarClock /> },
    { label: "Last success", value: source.lastSuccessAt, icon: <CheckCircle2 /> },
    { label: "Last error", value: source.lastErrorAt, icon: <TriangleAlert /> },
  ];
  const present = times.filter((entry) => entry.value);
  return (
    <div className="flex flex-col gap-3" data-source-state={source.state}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2">
          <StatusIcon status={display.status} size="sm" />
          <span className="min-w-0 truncate text-sm font-medium capitalize text-foreground">{source.id}</span>
        </div>
        <Badge intent={display.intent} size="md">
          {display.label}
        </Badge>
      </div>
      {source.reason ? <p className="text-sm text-muted-foreground">{source.reason}</p> : null}
      {present.length > 0 ? (
        <PropertyList className="text-sm">
          {present.map((entry) => (
            <PropertyRow key={entry.label}>
              <PropertyLabel icon={entry.icon}>{entry.label}</PropertyLabel>
              <PropertyValue>{formatConsoleTime(entry.value)}</PropertyValue>
            </PropertyRow>
          ))}
        </PropertyList>
      ) : null}
    </div>
  );
}

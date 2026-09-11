import { Badge } from "@/components/ui/badge";
import type { ApiSourceData } from "@/generated/read-api";

const intent = { healthy: "success", stale: "warning", unknown: "default", unavailable: "info", failed: "destructive" } as const;

export function SourceStatus({ source }: { source: ApiSourceData }) {
  return (
    <div className="space-y-2" data-source-state={source.state}>
      <div className="flex flex-wrap items-center justify-between gap-2"><span className="font-medium capitalize">{source.id}</span><Badge intent={intent[source.state]}>{source.state}</Badge></div>
      <p className="text-sm text-muted-foreground">{source.reason}</p>
      <p className="text-xs text-muted-foreground">Collected: {source.collectedAt ?? "No collection time available"}</p>
    </div>
  );
}

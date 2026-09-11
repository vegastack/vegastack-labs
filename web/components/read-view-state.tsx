"use client";

import type { ReactNode } from "react";
import { AlertTriangle, CircleOff, Clock3, LoaderCircle, PackageOpen, ShieldX } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";

export type ReadStateKind = "loading" | "empty" | "stale" | "unknown" | "unavailable" | "denied" | "partial" | "error";
const icons = { loading: LoaderCircle, empty: PackageOpen, stale: Clock3, unknown: CircleOff, unavailable: CircleOff, denied: ShieldX, partial: AlertTriangle, error: AlertTriangle } as const;

export function ReadViewState({ kind, title, description, staleData, onRetry }: { kind: ReadStateKind; title: string; description: string; staleData?: ReactNode; onRetry?: () => void }) {
  const Icon = icons[kind];
  return (
    <section className="space-y-4" aria-live="polite" role={kind === "denied" || kind === "error" ? "alert" : "status"} data-read-state={kind}>
      {staleData}
      <Empty bordered className="min-h-56 bg-card">
        <EmptyHeader>
          <EmptyMedia intent={kind === "error" || kind === "denied" ? "destructive" : "info"}><Icon aria-hidden className={kind === "loading" ? "animate-spin" : undefined} /></EmptyMedia>
          <EmptyTitle>{title}</EmptyTitle><EmptyDescription>{description}</EmptyDescription>
        </EmptyHeader>
        {onRetry ? <EmptyContent><Button className="min-h-11" variant="outline" onClick={onRetry}>Refresh</Button></EmptyContent> : null}
      </Empty>
    </section>
  );
}

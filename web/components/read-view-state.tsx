"use client";

import type { ReactNode } from "react";
import { AlertTriangle, CircleOff, Clock3, LoaderCircle, PackageOpen, ShieldX } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";

export type ReadStateKind = "loading" | "empty" | "stale" | "unknown" | "unavailable" | "denied" | "partial" | "error";

const icons = {
  loading: LoaderCircle,
  empty: PackageOpen,
  stale: Clock3,
  unknown: CircleOff,
  unavailable: CircleOff,
  denied: ShieldX,
  partial: AlertTriangle,
  error: AlertTriangle,
} as const;

// Empty's icon chip supports only default | info | destructive tints.
const mediaIntent = (kind: ReadStateKind) => (kind === "error" || kind === "denied" ? "destructive" : kind === "empty" ? "default" : "info");

export function ReadViewState({
  kind,
  title,
  description,
  staleData,
  onRetry,
}: {
  kind: ReadStateKind;
  title: string;
  description: string;
  staleData?: ReactNode;
  onRetry?: () => void;
}) {
  const Icon = icons[kind];
  const assertive = kind === "denied" || kind === "error";
  return (
    <div className="flex flex-col gap-4" data-read-state={kind}>
      <section aria-live={assertive ? "assertive" : "polite"} role={assertive ? "alert" : "status"}>
        <Empty variant="card" size="lg">
          <EmptyHeader>
            <EmptyMedia variant="icon" intent={mediaIntent(kind)}>
              <Icon aria-hidden className={kind === "loading" ? "animate-spin" : undefined} />
            </EmptyMedia>
            <EmptyTitle>{title}</EmptyTitle>
            <EmptyDescription>{description}</EmptyDescription>
          </EmptyHeader>
          {onRetry ? (
            <EmptyContent>
              <Button variant="outline" onClick={onRetry}>
                Refresh
              </Button>
            </EmptyContent>
          ) : null}
        </Empty>
      </section>
      {staleData}
    </div>
  );
}

import type { ReactNode } from "react";
import { AlertTriangle, CircleOff, LoaderCircle, PackageOpen } from "lucide-react";
import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";

export type ConsoleStateKind = "loading" | "empty" | "error" | "unavailable";
const icons = { loading: LoaderCircle, empty: PackageOpen, error: AlertTriangle, unavailable: CircleOff } as const;

export function ConsoleState({ kind, title, description, action }: { kind: ConsoleStateKind; title: string; description: string; action?: ReactNode }) {
  const Icon = icons[kind];
  const isAlert = kind === "error" || kind === "unavailable";
  return (
    <Empty bordered className="min-h-80 bg-card" role={isAlert ? "status" : undefined} aria-live={isAlert ? "polite" : undefined} data-console-state={kind}>
      <EmptyHeader>
        <EmptyMedia intent={isAlert ? "destructive" : "info"}><Icon aria-hidden className={kind === "loading" ? "animate-spin" : undefined} /></EmptyMedia>
        <EmptyTitle>{title}</EmptyTitle>
        <EmptyDescription>{description}</EmptyDescription>
      </EmptyHeader>
      {action ? <EmptyContent>{action}</EmptyContent> : null}
    </Empty>
  );
}

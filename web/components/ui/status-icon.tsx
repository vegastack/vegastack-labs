import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { Circle, CircleAlert, CircleCheck, Loader } from "lucide-react";
import { cn } from "@vegastack/design";

/**
 * StatusIcon variants — `status` selects the semantic color token, `size` maps
 * to the shared `size-*` scale. Color is conveyed through `currentColor`, so
 * every status maps to a semantic text token (no hardcoded hex, no raw
 * palette): `todo` → `text-muted-foreground`, `progress` → `text-info-text`,
 * `blocked` → `text-destructive-text`, `done` → `text-success-text`.
 */
export const statusIconVariants = cva("inline-block shrink-0", {
  variants: {
    status: {
      todo: "text-muted-foreground",
      progress: "text-info-text",
      blocked: "text-destructive-text",
      done: "text-success-text",
    },
    size: {
      xs: "size-3.5",
      sm: "size-4",
      default: "size-5",
      lg: "size-6",
    },
  },
  defaultVariants: { status: "todo", size: "default" },
});

/** The lucide icon rendered for each status. */
const STATUS_ICON = {
  todo: Circle,
  progress: Loader,
  blocked: CircleAlert,
  done: CircleCheck,
} as const;

/** Default accessible label per status, used when no `label` is supplied. */
const STATUS_LABEL: Record<
  NonNullable<VariantProps<typeof statusIconVariants>["status"]>,
  string
> = {
  todo: "To do",
  progress: "In progress",
  blocked: "Blocked",
  done: "Done",
};

/** Props accepted by `StatusIcon`. */
export interface StatusIconProps
  extends
    Omit<React.ComponentProps<"svg">, "color">,
    VariantProps<typeof statusIconVariants> {
  /**
   * Status to display. Selects both the icon and its semantic color token:
   * - `todo` → `Circle`, `text-muted-foreground`
   * - `progress` → spinning `Loader`, `text-info-text`
   * - `blocked` → `CircleAlert`, `text-destructive-text`
   * - `done` → `CircleCheck`, `text-success-text`
   * @default 'todo'
   */
  status?: "todo" | "progress" | "blocked" | "done";
  /**
   * Size variant — mirrors the rest of the scale and maps to the `size-*`
   * tokens.
   * @default 'default'
   */
  size?: "xs" | "sm" | "default" | "lg";
  /**
   * Accessible label announced by assistive tech. Defaults to a human-readable
   * name derived from `status` (e.g. `"In progress"`). Pass an empty string to
   * make the icon decorative (`aria-hidden`) — only do this when adjacent text
   * already conveys the status.

   * @default undefined
   */
  label?: string;
}

/**
 * `StatusIcon` — a small status indicator icon for the canonical task states
 * `todo` / `progress` / `blocked` / `done`. Each status maps to a `lucide-react`
 * icon and a semantic color token via `currentColor` (no hardcoded colors). The
 * `progress` status spins its `Loader` icon and respects
 * `prefers-reduced-motion` (`motion-reduce:animate-none`).
 *
 * Accessible by default: it renders `role="img"` with an `aria-label` derived
 * from `status` (or the `label` prop). When adjacent text already states the
 * status, pass `label=""` to mark the icon decorative (`aria-hidden`) and avoid
 * a redundant announcement.
 *
 * Pure presentational and server-safe — no hooks, no `'use client'`. Forwards
 * its ref to the underlying `<svg>`.
 *
 * @example
 * <StatusIcon status="done" label="Completed" />
 */
export function StatusIcon({
  className,
  status = "todo",
  size = "default",
  label,
  ref,
  ...props
}: StatusIconProps) {
  const Icon = STATUS_ICON[status];
  const resolvedLabel = label ?? STATUS_LABEL[status];
  const decorative = resolvedLabel === "";
  return (
    <Icon
      ref={ref}
      data-slot="status-icon"
      data-status={status}
      data-size={size}
      className={cn(
        statusIconVariants({ status, size }),
        status === "progress" && "animate-spin motion-reduce:animate-none",
        className,
      )}
      {...(decorative
        ? { "aria-hidden": true }
        : { role: "img", "aria-label": resolvedLabel })}
      {...props}
    />
  );
}

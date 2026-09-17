"use client";

import * as React from "react";
import { cva } from "class-variance-authority";
import { cn } from "@vegastack/design";

/* ------------------------------------------------------------------------------------------------
 * Stat — a labelled value block (Wave 2c, from the app-teardown record-highlights pattern):
 * `text-label-sm` muted label over a foreground value, with an HONEST empty treatment ("No
 * connection" in the faint register) instead of a dash. Server-safe, purely presentational.
 * Two scales: `default` (record-page highlights, 14px value) and `lg` (dashboard stat tiles,
 * 24px value on the type-scale cap).
 * ----------------------------------------------------------------------------------------------*/

export const statValueVariants = cva("font-medium text-foreground", {
  variants: {
    size: {
      md: "text-base",
      lg: "text-3xl tabular-nums",
    },
  },
  defaultVariants: { size: "md" },
});

const StatSizeContext = React.createContext<"md" | "lg">("md");

/** Props for a labelled statistic group. */
export interface StatProps extends React.ComponentPropsWithRef<"div"> {
  /**
   * Scale — `default` for facts/highlights rows, `lg` for dashboard tiles.
   * @default 'md'
   */
  size?: "md" | "lg";
}

/**
 * `Stat` — compose `StatLabel` + `StatValue` (or `StatEmpty` when there is no
 * value) and optionally `StatDelta` for a change indicator.
 *
 * @example
 * <Stat>
 *   <StatLabel>Estimated ARR</StatLabel>
 *   <StatValue>$1M–$10M</StatValue>
 * </Stat>
 *
 * @example
 * <Stat size="lg">
 *   <StatLabel>Active companies</StatLabel>
 *   <StatValue>1,284</StatValue>
 *   <StatDelta intent="up">+12% this month</StatDelta>
 * </Stat>
 */
export function Stat({ className, size = "md", ref, ...props }: StatProps) {
  return (
    <StatSizeContext.Provider value={size}>
      <div
        ref={ref}
        data-slot="stat"
        data-size={size}
        className={cn("flex min-w-0 flex-col gap-1", className)}
        {...props}
      />
    </StatSizeContext.Provider>
  );
}

/** Native props for the statistic label. */
export type StatLabelProps = React.ComponentPropsWithRef<"div">;

/** `StatLabel` — the muted label above the value. @example <StatLabel>Revenue</StatLabel> */
export function StatLabel({ className, ...props }: StatLabelProps) {
  return (
    <div
      data-slot="stat-label"
      className={cn("text-label-sm text-muted-foreground", className)}
      {...props}
    />
  );
}

/** Native props for the statistic value. */
export type StatValueProps = React.ComponentPropsWithRef<"div">;

/** `StatValue` — the value line. @example <StatValue>$1M</StatValue> */
export function StatValue({ className, ...props }: StatValueProps) {
  const size = React.useContext(StatSizeContext);
  return (
    <div
      data-slot="stat-value"
      className={cn(statValueVariants({ size }), className)}
      {...props}
    />
  );
}

/** Native props for an honest empty statistic value. */
export type StatEmptyProps = React.ComponentPropsWithRef<"div">;

/**
 * `StatEmpty` — the honest empty value ("No connection", "No team"): a muted,
 * contrast-safe phrase instead of a dash or a zero that would read as data.
 * @example <StatEmpty>No connection</StatEmpty>
 */
export function StatEmpty({ className, children, ...props }: StatEmptyProps) {
  return (
    <div
      data-slot="stat-empty"
      className={cn("text-base text-muted-foreground", className)}
      {...props}
    >
      {children ?? "No data"}
    </div>
  );
}

/** Props for a directional change line beneath a statistic. */
export interface StatDeltaProps extends React.ComponentPropsWithRef<"div"> {
  /**
   * Direction of the change — `up` reads success, `down` reads destructive,
   * `flat` stays muted. Pair the copy with a sign/arrow; color is never the
   * only signal.
   * @default 'flat'
   */
  intent?: "up" | "down" | "flat";
}

const DELTA_CLASSES: Record<NonNullable<StatDeltaProps["intent"]>, string> = {
  up: "text-success-text",
  down: "text-destructive-text",
  flat: "text-muted-foreground",
};

/** `StatDelta` — a small change line. @example <StatDelta intent="up">+12%</StatDelta> */
export function StatDelta({
  className,
  intent = "flat",
  ...props
}: StatDeltaProps) {
  return (
    <div
      data-slot="stat-delta"
      data-intent={intent}
      className={cn("text-sm font-medium", DELTA_CLASSES[intent], className)}
      {...props}
    />
  );
}

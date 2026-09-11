"use client";

import * as React from "react";
import { cn } from "@vegastack/design";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";

/** Parse a `Date | string | number` input into a `Date`. */
function toDate(date: Date | string | number): Date {
  return date instanceof Date ? date : new Date(date);
}

/** Milliseconds per unit — named so the unit-picker reads clearly. */
const MS = {
  second: 1_000,
  minute: 60_000,
  hour: 3_600_000,
  day: 86_400_000,
  week: 604_800_000,
  month: 2_592_000_000,
  year: 31_536_000_000,
} as const;

/** Ordered `[unit, ms-per-unit]` thresholds, largest → smallest. */
const DIVISIONS: ReadonlyArray<readonly [Intl.RelativeTimeFormatUnit, number]> =
  [
    ["year", MS.year],
    ["month", MS.month],
    ["week", MS.week],
    ["day", MS.day],
    ["hour", MS.hour],
    ["minute", MS.minute],
    ["second", MS.second],
  ];

/**
 * Pick the largest whole unit for a signed millisecond delta and format it with
 * `Intl.RelativeTimeFormat` → `"2 hours ago"`, `"in 3 days"`. A delta under one
 * minute collapses to a localized `"now"` (`format(0, 'second')` with
 * `numeric: 'auto'`).
 *
 * @param deltaMs - `target − now` in ms (negative = past, positive = future).
 */
function formatAgo(deltaMs: number, rtf: Intl.RelativeTimeFormat): string {
  if (Math.abs(deltaMs) < MS.minute) return rtf.format(0, "second");
  for (const [unit, ms] of DIVISIONS) {
    if (Math.abs(deltaMs) >= ms || unit === "second") {
      return rtf.format(Math.round(deltaMs / ms), unit);
    }
  }
  return rtf.format(0, "second");
}

/**
 * Calendar-day label for the `day` mode: `"today"` / `"yesterday"` / `"tomorrow"`
 * for the adjacent days (via `Intl.RelativeTimeFormat`'s `numeric: 'auto'`), and
 * an absolute `"March 15"` / `"March 15, 2025"` for anything further out.
 */
function formatDay(
  target: Date,
  now: Date,
  locale: string | string[] | undefined,
  rtf: Intl.RelativeTimeFormat,
): string {
  const startOf = (d: Date) =>
    Date.UTC(d.getFullYear(), d.getMonth(), d.getDate());
  const dayDelta = Math.round((startOf(target) - startOf(now)) / MS.day);

  if (Math.abs(dayDelta) <= 1) {
    // numeric: 'auto' yields "today"/"yesterday"/"tomorrow" for -1..1.
    return rtf.format(dayDelta, "day");
  }
  const sameYear = target.getFullYear() === now.getFullYear();
  return new Intl.DateTimeFormat(locale, {
    month: "long",
    day: "numeric",
    ...(sameYear ? {} : { year: "numeric" }),
  }).format(target);
}

/**
 * Refresh cadence (ms) for a live timestamp, by age. Recent timestamps tick
 * faster (where the displayed value changes often), older ones slower.
 * `0` disables the timer.
 */
function tickInterval(deltaMs: number): number {
  const abs = Math.abs(deltaMs);
  if (abs < MS.hour) return 10_000; // < 1 hour: every 10s
  if (abs < MS.day) return 60_000; // < 1 day:  every 1min
  return 0; // ≥ 1 day: static, no timer needed
}

/** Props accepted by `RelativeTime`. */
export interface RelativeTimeProps extends Omit<
  React.ComponentPropsWithRef<"time">,
  "title" | "children"
> {
  /**
   * The instant to render, relative to `now`. Accepts a `Date`, an ISO string,
   * or an epoch-millisecond number.
   */
  date: Date | string | number;
  /**
   * Formatting mode.
   * - `ago`: duration-relative — `"2 hours ago"`, `"in 3 days"`.
   * - `day`: calendar-relative — `"today"`, `"yesterday"`, else an absolute date.
   * @default 'ago'
   */
  mode?: "ago" | "day";
  /**
   * Unit length, mapped to `Intl.RelativeTimeFormat`'s `style` — `'long'` gives
   * `"2 hours ago"`, `'short'` `"2 hr. ago"`, `'narrow'` the compact `"2h ago"`
   * (dense tables, activity feeds). Applies to `mode="day"`'s relative words too.
   * @default 'long'
   */
  unitStyle?: "long" | "short" | "narrow";
  /**
   * Reference instant the relative string is measured against, as epoch ms.
   * Defaults to the live clock (`Date.now()`); pass a fixed value to render
   * deterministically (tests, SSR snapshots, storybook).
   * @default Date.now()
   */
  now?: number;
  /**
   * Auto-refresh the displayed value on a timer while the date is recent (faster
   * near "now", off once it is a day old). Ignored when `now` is provided.
   * @default true
   */
  refresh?: boolean;
  /**
   * BCP-47 locale(s) for `Intl` formatting. Defaults to the runtime locale.

   * @default undefined
   */
  locale?: string | string[];
  /**
   * Reveal the absolute date/time in a Tooltip on hover/focus.
   * - `true`: a localized full date-time (`"March 15, 2025, 2:30 PM"`).
   * - a string: your own label.
   * - `false`: no tooltip.
   * @default true
   */
  title?: boolean | string;
  /**
   * How long to wait (ms) before the tooltip opens on hover. `0` reveals the
   * absolute date instantly. Ignored when `title` is `false`.
   * @default 0
   */
  tooltipDelay?: number;
}

/**
 * `RelativeTime` — render an instant as a human-relative string using the native
 * `Intl.RelativeTimeFormat` (no date library). `mode="ago"` gives duration-relative
 * copy (`"2 hours ago"`, `"in 3 days"`); `mode="day"` gives calendar-relative copy
 * (`"today"`, `"yesterday"`, else an absolute date).
 *
 * Renders a semantic `<time dateTime>` so the machine-readable ISO timestamp is
 * always present. Self-updating: while the date is recent it refreshes on a timer
 * (off once it is a day old), and an absolute date-time is revealed in a Tooltip
 * by default. Purely presentational — text inherits color from its context.
 *
 * @example
 * <RelativeTime date={comment.createdAt} />            // "2 hours ago"
 * <RelativeTime date={dueDate} mode="day" />            // "tomorrow" / "March 15"
 * <RelativeTime date={ts} now={FIXED} refresh={false} /> // deterministic
 *
 * **Announcements (register P2-40, deliberate):** the periodic re-render is intentionally
 * SILENT to assistive tech — no `aria-live`. A ticking timestamp that announced every minute
 * would be noise; the absolute time is always available via the Tooltip (keyboard-reachable)
 * and the `dateTime` attribute. Wrap in your own `role="status"` region only if a specific
 * surface genuinely needs announced updates.
 */
export function RelativeTime({
  date,
  mode = "ago",
  unitStyle = "long",
  now,
  refresh = true,
  locale,
  title = true,
  tooltipDelay = 0,
  className,
  ref,
  ...props
}: RelativeTimeProps) {
  const target = React.useMemo(() => toDate(date), [date]);
  const targetMs = target.getTime();
  const localeKey = Array.isArray(locale) ? locale.join(",") : locale;

  // When `now` is provided the output is deterministic (no clock, no timer).
  const isControlled = now !== undefined;

  // Uncontrolled live time cannot be reproduced by the server at hydration.
  // Start from a deterministic empty state on both sides, then reveal the live
  // label after mount. Controlled `now` output remains server-renderable.
  const [hydrated, setHydrated] = React.useState(isControlled);
  const [clock, setClock] = React.useState(() => now ?? 0);

  const rtf = React.useMemo(
    () =>
      new Intl.RelativeTimeFormat(locale, {
        numeric: "auto",
        style: unitStyle,
      }),
    [localeKey, unitStyle], // eslint-disable-line react-hooks/exhaustive-deps -- locale array compared by joined key
  );

  React.useEffect(() => {
    if (isControlled) return;
    setClock(Date.now());
    setHydrated(true);
    if (!refresh) return;
    // Resync clock on mount + reschedule adaptive tick. (set-state-in-effect is
    // intentional here; the rule is not enabled in @vegastack/eslint-config.)
    let timerId: ReturnType<typeof setTimeout>;
    const schedule = () => {
      const interval = tickInterval(targetMs - Date.now());
      if (interval === 0) return; // old enough that the value no longer changes
      timerId = setTimeout(() => {
        setClock(Date.now());
        schedule();
      }, interval);
    };
    schedule();
    return () => clearTimeout(timerId);
  }, [isControlled, refresh, targetMs]);

  const nowMs = isControlled ? now : clock;
  const nowDate = React.useMemo(() => new Date(nowMs), [nowMs]);

  const isValid = !Number.isNaN(targetMs);
  const isPendingHydration = !isControlled && !hydrated;
  const display =
    !isValid || isPendingHydration
      ? ""
      : mode === "day"
        ? formatDay(target, nowDate, locale, rtf)
        : formatAgo(targetMs - nowMs, rtf);

  const isoString = isValid ? target.toISOString() : undefined;
  const hasTooltip = Boolean(title) && isValid;

  const timeEl = (
    <time
      ref={ref}
      data-slot="relative-time"
      data-mode={mode}
      dateTime={isoString}
      aria-busy={isPendingHydration || undefined}
      // When wrapped in a Tooltip the <time> becomes the trigger; it must be
      // focusable so keyboard users can reveal the absolute date.
      tabIndex={hasTooltip ? 0 : undefined}
      className={cn(
        "relative inline-flex rounded-sm tabular-nums before:absolute before:inset-x-0 before:-inset-y-1",
        className,
      )}
      {...props}
    >
      {display}
    </time>
  );

  if (!hasTooltip) return timeEl;

  const tooltipLabel =
    typeof title === "string"
      ? title
      : new Intl.DateTimeFormat(locale, {
          dateStyle: "long",
          timeStyle: "short",
        }).format(target);

  return (
    <Tooltip delay={tooltipDelay}>
      <TooltipTrigger render={timeEl} />
      <TooltipContent>{tooltipLabel}</TooltipContent>
    </Tooltip>
  );
}

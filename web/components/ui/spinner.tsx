import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { Loader } from "lucide-react";
import { cn } from "@vegastack/design";

/**
 * Spinner size scale — mirrors the rest of the system (`xs`/`sm`/`default`/`lg`)
 * and maps to the `size-*` token scale. A STANDALONE spinner defaults to
 * `text-muted-foreground` (secondary chrome); `size="inherit"` — the in-control
 * form Button/Badge/Combobox use — inherits BOTH the host's `[&_svg]` sizing and
 * its `currentColor`. The color half is load-bearing: a muted-gray spinner inside
 * a `bg-primary text-primary-foreground` button is invisible in light mode
 * (dark-on-dark) — the loading glyph must read in the host's own ink.
 */
export const spinnerVariants = cva(
  "shrink-0 animate-spin text-muted-foreground",
  {
    variants: {
      size: {
        xs: "size-(--icon-compact)",
        sm: "size-(--icon-inline)",
        md: "size-(--icon-default)",
        lg: "size-(--icon-feature)",
        /**
         * No size class — the host's `[&_svg]` selector sizing applies (Button/Badge) —
         * and `text-current` so the spinner spins in the host's ink, not detached gray.
         */
        inherit: "text-current",
      },
    },
    defaultVariants: { size: "md" },
  },
);

/** Props accepted by `Spinner`. */
export interface SpinnerProps
  extends
    Omit<React.ComponentProps<"svg">, "color">,
    VariantProps<typeof spinnerVariants> {
  /**
   * Size variant — mirrors the rest of the scale and maps to the `size-*`
   * tokens. The spinner inherits `currentColor`, so set its color via the
   * parent's text color.
   * @default 'md'
   */
  size?: "xs" | "sm" | "md" | "lg" | "inherit";
  /**
   * Accessible label announced by assistive tech while the spinner is visible. The spinner
   * exposes `role="status"` + `aria-label` so screen readers announce the loading state.
   * @default 'Loading'
   */
  label?: string;
  /**
   * Marks the spinner as decoration: `aria-hidden`, no role, no label. Use it when the
   * surrounding UI already announces the loading state — a button with loading text, or a
   * sibling live region that says "Saving…" — so the announcement is not made twice.
   *
   * This is the sanctioned way to say it (audit B8-09). `label=""` also works and means the
   * same thing, but it says it by passing a value that reads as a mistake at the call site.
   * @default false
   */
  decorative?: boolean;
}

/**
 * `Spinner` — an indeterminate loading indicator. A spinning `lucide-react`
 * `Loader` icon that defaults to `text-muted-foreground` (overridable via an
 * ancestor text color or a `className`, since it draws in `currentColor`) and
 * freezes under `prefers-reduced-motion` via the global `base.css` reset. Four sizes
 * (`xs`/`sm`/`default`/`lg`).
 *
 * Accessible by default: it renders `role="status"` with an `aria-label`
 * (default `"Loading"`) so the loading state is announced. When the surrounding
 * UI already labels the loading region — e.g. a button with loading text — pass
 * `decorative` to hide it from assistive tech (`aria-hidden`) and avoid a double
 * announcement.
 *
 * Pure presentational and server-safe — no hooks, no `'use client'`. Forwards
 * its ref to the underlying `<svg>`.
 *
 * @example
 * <Spinner label="Saving" size="sm" />
 */
export function Spinner({
  className,
  size = "md",
  label = "Loading",
  decorative: decorativeProp = false,
  ref,
  ...props
}: SpinnerProps) {
  const decorative = decorativeProp || label === "";
  return (
    <Loader
      ref={ref}
      data-slot="spinner"
      data-size={size}
      className={cn(spinnerVariants({ size }), className)}
      {...(decorative
        ? { "aria-hidden": true }
        : { role: "status", "aria-label": label })}
      {...props}
    />
  );
}

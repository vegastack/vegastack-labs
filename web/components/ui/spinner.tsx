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
  "shrink-0 animate-spin text-muted-foreground motion-reduce:animate-none",
  {
    variants: {
      size: {
        xs: "size-(--icon-compact)",
        sm: "size-(--icon-inline)",
        default: "size-(--icon-default)",
        lg: "size-(--icon-feature)",
        /**
         * No size class — the host's `[&_svg]` selector sizing applies (Button/Badge) —
         * and `text-current` so the spinner spins in the host's ink, not detached gray.
         */
        inherit: "text-current",
      },
    },
    defaultVariants: { size: "default" },
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
   * @default 'default'
   */
  size?: "xs" | "sm" | "default" | "lg" | "inherit";
  /**
   * Accessible label announced by assistive tech while the spinner is visible.
   * When provided, the spinner exposes `role="status"` + `aria-label` so screen
   * readers announce the loading state. Pass an empty string (or rely on a
   * sibling that already labels the loading region) to make the spinner purely
   * decorative — it is then hidden with `aria-hidden`.
   * @default 'Loading'
   */
  label?: string;
}

/**
 * `Spinner` — an indeterminate loading indicator. A spinning `lucide-react`
 * `Loader` icon that defaults to `text-muted-foreground` (overridable via an
 * ancestor text color or a `className`, since it draws in `currentColor`) and
 * respects `prefers-reduced-motion` (`motion-reduce:animate-none`). Four sizes
 * (`xs`/`sm`/`default`/`lg`).
 *
 * Accessible by default: it renders `role="status"` with an `aria-label`
 * (default `"Loading"`) so the loading state is announced. When the surrounding
 * UI already labels the loading region — e.g. a button with loading text — pass
 * `label=""` to mark the spinner decorative (`aria-hidden`) and avoid a double
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
  size = "default",
  label = "Loading",
  ref,
  ...props
}: SpinnerProps) {
  const decorative = label === "";
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

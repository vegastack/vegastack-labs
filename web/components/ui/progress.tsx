import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { Progress as BaseProgress } from "@base-ui/react/progress";
import { cn } from "@vegastack/design";

/**
 * Progress track variants — the inset rail that holds the indicator. State and
 * sizing are token-driven (`bg-muted`, the height scale) — no hardcoded colors
 * or pixel values. `overflow-hidden` clips the indicator to the rounded track.
 */
export const progressVariants = cva(
  "relative w-full overflow-hidden rounded-full bg-muted",
  {
    variants: {
      size: {
        sm: "h-1.5",
        md: "h-2",
        lg: "h-3",
      },
    },
    defaultVariants: { size: "md" },
  },
);

/** Track height per size — kept in sync with `progressVariants` for JSDoc. */
export type ProgressSize = NonNullable<
  VariantProps<typeof progressVariants>["size"]
>;

/** Props accepted by `Progress`. */
export interface ProgressProps
  extends
    Omit<React.ComponentProps<typeof BaseProgress.Root>, "value">,
    VariantProps<typeof progressVariants> {
  /**
   * Current completion value, between `0` and `max`. Pass `null` for an
   * indeterminate bar (Base UI sets `data-indeterminate` and drops
   * `aria-valuenow`).
   * @default null
   */
  value?: number | null;
  /**
   * Upper bound of the scale — `value` is reported as `value / max`.
   * @default 100
   */
  max?: number;
  /**
   * Track + indicator height. `sm` (6px), `md` (8px), `lg` (12px).
   * @default 'md'
   */
  size?: ProgressSize;
  /**
   * Classes for the inner track rail. Use this for track width/height/color
   * overrides; `className` belongs to the root progressbar element.

   * @default undefined
   */
  trackClassName?: string;
  /**
   * Classes for the fill indicator. Use this to change the fill token or motion
   * treatment without replacing the accessible progress root.

   * @default undefined
   */
  indicatorClassName?: string;
  /**
   * Replace the rendered root element via Base UI `render` composition. Pass a
   * `ReactElement` or a render function — Base UI merges this
   * wrapper's `data-slot` and state `data-*` onto your element, forwards the ref,
   * and keeps the `<Progress.Track>` / `<Progress.Indicator>` children. The
   * element must support `role="progressbar"` semantics.

   * @default undefined
   */
  render?: React.ComponentProps<typeof BaseProgress.Root>["render"];
}

/**
 * `Progress` — a determinate horizontal progress bar built on Base UI's
 * `Progress` (`Root` + `Track` + `Indicator`). Use it to communicate the
 * completion of an ongoing, measurable task (file upload, multi-step form,
 * onboarding checklist).
 *
 * Renders a `role="progressbar"` with `aria-valuenow` / `aria-valuemin` /
 * `aria-valuemax` managed by Base UI — pass `null` for an indeterminate state.
 * Always give it an accessible name (`aria-label`, or an associated label).
 *
 * Indeterminate is a distinct visual, not a full bar: the indicator becomes a
 * 35%-wide segment sweeping the track (`motion-indeterminate`), and Base UI drops
 * `aria-valuenow`. Under `prefers-reduced-motion` the global reset collapses the
 * loop to its resting frame — a static 35% segment — so the bar still cannot be
 * mistaken for "complete".
 *
 * @example
 * // determinate
 * <Progress value={60} aria-label="Upload progress" />
 *
 * @example
 * // custom scale + size
 * <Progress value={3} max={5} size="lg" aria-label="Step 3 of 5" />
 *
 * @example
 * // indeterminate
 * <Progress value={null} aria-label="Loading" />
 */
export function Progress({
  className,
  trackClassName,
  indicatorClassName,
  size = "md",
  value = null,
  max = 100,
  ref,
  ...props
}: ProgressProps) {
  return (
    <BaseProgress.Root
      ref={ref}
      data-slot="progress"
      data-size={size}
      value={value}
      max={max}
      className={cn("w-full", className)}
      {...props}
    >
      <BaseProgress.Track
        data-slot="progress-track"
        className={cn(progressVariants({ size }), trackClassName)}
      >
        <BaseProgress.Indicator
          data-slot="progress-indicator"
          className={cn(
            "h-full rounded-full bg-primary transition-[width] duration-base ease-standard",
            // Indeterminate (audit B2-01): Base UI writes NO inline width when `value` is
            // null, so the indicator would otherwise inherit the track's full width and read
            // as 100% complete. Take it out of flow and give it its own 35% segment that
            // sweeps the track on the one sanctioned loop. `transition-[width]` above is inert
            // here — there is no width to interpolate.
            "data-indeterminate:absolute data-indeterminate:inset-y-0 data-indeterminate:w-[35%] data-indeterminate:motion-indeterminate",
            indicatorClassName,
          )}
        />
      </BaseProgress.Track>
    </BaseProgress.Root>
  );
}

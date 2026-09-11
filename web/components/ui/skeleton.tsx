import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@vegastack/design";

/**
 * Skeleton variants — the `shape` of a single loading placeholder. Every value
 * is a semantic token (`bg-muted`, `rounded-*`) — no hardcoded colors or sizes.
 * The pulse uses `animate-pulse` and is suppressed under `prefers-reduced-motion`
 * via `motion-reduce:animate-none`.
 */
export const skeletonVariants = cva(
  "block shrink-0 bg-muted animate-pulse motion-reduce:animate-none",
  {
    variants: {
      shape: {
        /** A single text line — full width, line-height tall, fully rounded. */
        line: "h-4 w-full rounded-md",
        /** A circular placeholder (avatar/icon) — square footprint, full radius. */
        circle: "size-(--size-lg) rounded-full",
        /** A rectangular block (image/thumbnail) — fills its container. */
        rect: "h-24 w-full rounded-md",
        /** A larger surface (card body) — taller block. */
        card: "h-40 w-full rounded-lg",
      },
    },
    defaultVariants: { shape: "line" },
  },
);

/** Shape tokens Skeleton supports. */
export type SkeletonShape = NonNullable<
  VariantProps<typeof skeletonVariants>["shape"]
>;

/** Props accepted by `Skeleton`. */
export interface SkeletonProps
  extends
    Omit<React.ComponentPropsWithRef<"div">, "children">,
    VariantProps<typeof skeletonVariants> {
  /**
   * Placeholder shape.
   * - `line`: a single text line (default).
   * - `circle`: a circular avatar/icon placeholder.
   * - `rect`: a rectangular image/thumbnail block.
   * - `card`: a larger card-surface block.
   * @default "line"
   */
  shape?: SkeletonShape;
  /**
   * Render this many stacked placeholders. With `count > 1`, a vertical stack of
   * `count` skeletons is rendered (the last `line` is shortened to mimic a
   * paragraph). Useful for multi-line text blocks.
   * @default 1
   */
  count?: number;
}

/**
 * `Skeleton` — a token-driven loading placeholder with a `pulse` animation.
 * Decorative by default (`aria-hidden`, `role="presentation"`) so screen readers
 * skip it; pair it with an `aria-busy` region and a visually-hidden "Loading…"
 * label on the live container. Server-safe (no hooks, no `'use client'`).
 *
 * @example
 * // single line
 * <Skeleton />
 *
 * @example
 * // three-line paragraph
 * <Skeleton count={3} />
 *
 * @example
 * // avatar + two lines (an item row)
 * <div className="flex items-center gap-3">
 *   <Skeleton shape="circle" />
 *   <div className="flex flex-1 flex-col gap-2">
 *     <Skeleton className="w-1/2" />
 *     <Skeleton className="w-3/4" />
 *   </div>
 * </div>
 */
export function Skeleton({
  className,
  shape = "line",
  count = 1,
  ref,
  ...props
}: SkeletonProps) {
  const lines = Number.isFinite(count) ? Math.max(1, Math.floor(count)) : 1;

  if (lines === 1) {
    return (
      <div
        ref={ref}
        role="presentation"
        aria-hidden="true"
        data-slot="skeleton"
        data-shape={shape}
        className={cn(skeletonVariants({ shape }), className)}
        {...props}
      />
    );
  }

  return (
    <div
      ref={ref}
      role="presentation"
      aria-hidden="true"
      data-slot="skeleton"
      data-shape={shape}
      data-count={lines}
      className={cn("flex flex-col gap-2", className)}
      {...props}
    >
      {Array.from({ length: lines }, (_, i) => (
        <div
          key={i}
          data-slot="skeleton-line"
          // Shorten the final line to mimic the ragged end of a paragraph.
          className={cn(
            skeletonVariants({ shape }),
            i === lines - 1 && shape === "line" && "w-4/5",
          )}
        />
      ))}
    </div>
  );
}

/* ---------------------------------------------------------------------------------------------
 * SkeletonReveal — the "skeleton reveal" pattern (audit 09 §d5). `Skeleton` itself stays a static
 * placeholder; the reveal motion belongs to the content that REPLACES it. This wrapper keys the
 * loading/content branches so swapping from one to the other always remounts (never just patches
 * props in place), and the content branch carries `motion-enter-up` so it fades + rises in instead
 * of popping flatly into place.
 *
 * This is a thin convenience, not a new pattern: the equivalent is one line inline —
 *   {loading ? <Skeleton /> : <div className="motion-enter-up">{content}</div>}
 * — reach for that instead when you don't need the shared wrapper (e.g. the content root already
 * needs its own distinct element/props per branch).
 * ------------------------------------------------------------------------------------------- */

/** Props accepted by `SkeletonReveal`. */
export interface SkeletonRevealProps extends Omit<
  React.ComponentPropsWithRef<"div">,
  "children"
> {
  /**
   * Whether the skeleton placeholder (vs. the real content) should render.
   * Flip this to `false` once the data has arrived.
   */
  loading: boolean;
  /**
   * The placeholder shown while `loading` is `true` — typically one or more
   * `<Skeleton>` elements shaped like the content they stand in for.
   */
  skeleton: React.ReactNode;
  /**
   * The real content, rendered — and gently revealed via `motion-enter-up` —
   * once `loading` is `false`.

   * @default undefined
   */
  children?: React.ReactNode;
}

/**
 * `SkeletonReveal` — swaps a `Skeleton` placeholder for real content and lets
 * the content arrive with a subtle fade + rise (`motion-enter-up`) instead of
 * popping in flatly. `ref`, `className`, and any other `div` props apply to
 * the content wrapper only — there's no host element to ref while `loading`.
 *
 * @example
 * <SkeletonReveal loading={isLoading} skeleton={<Skeleton count={3} />}>
 *   <Article content={data} />
 * </SkeletonReveal>
 */
export function SkeletonReveal({
  loading,
  skeleton,
  children,
  className,
  ref,
  ...props
}: SkeletonRevealProps) {
  if (loading) {
    // Fragment: no wrapper element while loading, so `skeleton` renders exactly as passed.
    return <React.Fragment key="skeleton">{skeleton}</React.Fragment>;
  }

  return (
    <div
      key="content"
      ref={ref}
      data-slot="skeleton-reveal-content"
      className={cn("motion-enter-up", className)}
      {...props}
    >
      {children}
    </div>
  );
}

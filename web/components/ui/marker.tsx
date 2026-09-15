"use client";

import * as React from "react";
import { useRender } from "@base-ui/react/use-render";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@vegastack/design";

/* ------------------------------------------------------------------------------------------------
 * Marker variants — an inline conversation marker for status lines, system notes, and labelled
 * dividers inside a thread. Every value is a semantic token (`text-muted-foreground`, `bg-border`) —
 * no hardcoded colours. The root is a `group/marker` so `MarkerContent` can react to the chosen
 * `variant` via `group-data-[variant=…]/marker`. A nested `<a>` is underlined and brightens to
 * `text-foreground` on hover so a marker rendered as a link reads as interactive.
 * ----------------------------------------------------------------------------------------------*/

export const markerVariants = cva(
  "group/marker relative flex min-h-4 w-full items-center gap-2 text-left text-base text-muted-foreground [&_svg:not([class*='size-'])]:size-(--icon-default) [a]:underline [a]:underline-offset-3 [a]:hover:text-foreground",
  {
    variants: {
      variant: {
        /**
         * A plain inline marker for status, notes, and actions.
         *
         * A marker rendered as a link or a button IS the control, and one line of
         * `text-base` is a 21px box — under the 24px pointer-target floor (WCAG 2.2
         * §2.5.8). `:is(a, button)` adds an invisible `::before` hit area to exactly
         * those cases, so the row measures 29px to the pointer and not one pixel
         * differently to the eye. It is scoped to this variant (and `border`) rather
         * than the base because `separator` spends both pseudo-elements on its divider
         * lines. Measured: 270.00x21.00 -> 270.00x29.00.
         */
        default:
          "[&:is(a,button)]:before:absolute [&:is(a,button)]:before:inset-x-0 [&:is(a,button)]:before:-inset-y-1",
        /** A centred label flanked by divider lines on each side. */
        separator:
          "before:mr-1 before:h-px before:min-w-0 before:flex-1 before:bg-border after:ml-1 after:h-px after:min-w-0 after:flex-1 after:bg-border",
        /** A marker with a bottom hairline under the row. Same hit area as `default`. */
        border:
          "border-b border-border pb-2 [&:is(a,button)]:before:absolute [&:is(a,button)]:before:inset-x-0 [&:is(a,button)]:before:-inset-y-1",
      },
    },
    defaultVariants: { variant: "default" },
  },
);

/** Layout style a `Marker` can take. */
export type MarkerVariant = NonNullable<
  VariantProps<typeof markerVariants>["variant"]
>;

/** Props accepted by `Marker`. */
export interface MarkerProps
  extends
    React.ComponentPropsWithRef<"div">,
    VariantProps<typeof markerVariants> {
  /**
   * Layout style.
   * - `default`: a plain inline marker (default).
   * - `separator`: a centred label with divider lines either side.
   * - `border`: a row with a bottom hairline.
   * @default 'default'
   */
  variant?: MarkerVariant;
  /**
   * Render the marker as a different element (e.g. a link or button) via Base UI
   * `render` composition. Pass a `ReactElement` or a render function.

   * @default undefined
   */
  render?: useRender.RenderProp;
  /**
   * Opt-in mount animation (`motion-pop-in`) for a marker that appears in
   * response to a real event — a status note that just landed, a new "Today"
   * divider inserted at the head of a thread. **Default off**: markers that are
   * part of an already-rendered thread history must not pop on initial page
   * load. Set it only for a marker whose own appearance is the signal (mirrors
   * `Badge`'s `animateIn`).
   * @default false
   */
  animateIn?: boolean;
}

/**
 * `Marker` — an inline conversation marker: a status line, a system note, a
 * labelled divider, or an action row inside a message thread. Built on Base UI
 * `useRender`, so it stays polymorphic — pass `render={<a href="…" />}` to turn
 * the whole row into a link, or `render={<button />}` for an action. Pair the
 * text with the `shimmer` utility for streaming copy, or with a `Spinner` /
 * `MarkerIcon` for progress. Pass `animateIn` to pop the marker in on mount when
 * its appearance is itself the event (off by default).
 *
 * @example
 * <Marker><MarkerIcon><CheckIcon /></MarkerIcon><MarkerContent>Merged</MarkerContent></Marker>
 *
 * @example
 * // a labelled divider between groups of messages
 * <Marker variant="separator"><MarkerContent>Today</MarkerContent></Marker>
 *
 * @example
 * // the whole row as a link
 * <Marker render={<a href="#" />}><MarkerContent>View the pull request</MarkerContent></Marker>
 */
export function Marker({
  className,
  variant = "default",
  render,
  animateIn = false,
  ref,
  ...props
}: MarkerProps) {
  return useRender({
    render: render ?? <div />,
    defaultTagName: "div",
    ref, // forward the consumer ref onto the rendered (or composed) element
    props: {
      "data-slot": "marker",
      "data-variant": variant,
      className: cn(
        markerVariants({ variant }),
        animateIn && "motion-pop-in",
        className,
      ),
      ...props,
    },
  });
}

/** Props accepted by `MarkerIcon`. */
export type MarkerIconProps = React.ComponentPropsWithRef<"span">;

/**
 * `MarkerIcon` — the leading icon slot for a `Marker`. Decorative by default
 * (`aria-hidden`) so screen readers skip it; the adjacent `MarkerContent` text
 * carries the meaning. Sizes the slot and any bare `svg` child with the default icon role.
 * @example <MarkerIcon><Check aria-hidden /></MarkerIcon>
 */
export function MarkerIcon({ className, ref, ...props }: MarkerIconProps) {
  return (
    <span
      ref={ref}
      data-slot="marker-icon"
      aria-hidden="true"
      className={cn(
        "size-(--icon-default) shrink-0 [&_svg:not([class*='size-'])]:size-(--icon-default)",
        className,
      )}
      {...props}
    />
  );
}

/** Props accepted by `MarkerContent`. */
export type MarkerContentProps = React.ComponentPropsWithRef<"span">;

/**
 * `MarkerContent` — the text content of a `Marker`. Wraps long content and,
 * under the `separator` variant, centres itself between the divider lines. Any
 * nested `<a>` inherits the underlined, hover-brightening link affordance.
 * @example <MarkerContent>Connected</MarkerContent>
 */
export function MarkerContent({
  className,
  ref,
  ...props
}: MarkerContentProps) {
  return (
    <span
      ref={ref}
      data-slot="marker-content"
      className={cn(
        "min-w-0 wrap-break-word group-data-[variant=separator]/marker:flex-none group-data-[variant=separator]/marker:text-center *:[a]:underline *:[a]:underline-offset-3 *:[a]:hover:text-foreground",
        className,
      )}
      {...props}
    />
  );
}

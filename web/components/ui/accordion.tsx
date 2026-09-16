"use client";

import * as React from "react";
import { Accordion as BaseAccordion } from "@base-ui/react/accordion";
import { ChevronDown } from "lucide-react";
import { cn, surfaceInteractive } from "@vegastack/design";

/* ------------------------------------------------------------------------------------------------
 * Accordion (Root) — groups the collapsible items and owns single/multiple open behavior.
 * ----------------------------------------------------------------------------------------------*/

/** Props accepted by `Accordion`. */
export type AccordionProps = React.ComponentProps<typeof BaseAccordion.Root>;

/**
 * `Accordion` — the root that groups a stack of collapsible `AccordionItem`s.
 * Flat, shadcn-style API over Base UI Accordion:
 * `Accordion` → `AccordionItem` → `AccordionTrigger` + `AccordionContent`.
 *
 * Single-open by default; pass Base UI's `multiple` prop when more than one
 * item can stay open at the same time. Controlled via `value`/`onValueChange`,
 * or uncontrolled via `defaultValue` (both arrays).
 *
 * @example
 * <Accordion defaultValue={['shipping']}>
 *   <AccordionItem value="shipping">
 *     <AccordionTrigger>Shipping</AccordionTrigger>
 *     <AccordionContent>Ships in 2–3 business days.</AccordionContent>
 *   </AccordionItem>
 *   <AccordionItem value="returns">
 *     <AccordionTrigger>Returns</AccordionTrigger>
 *     <AccordionContent>30-day return window.</AccordionContent>
 *   </AccordionItem>
 * </Accordion>
 */
export function Accordion({ className, ref, ...props }: AccordionProps) {
  return (
    <BaseAccordion.Root
      ref={ref}
      data-slot="accordion"
      className={cn("w-full", className)}
      {...props}
    />
  );
}

/* ------------------------------------------------------------------------------------------------
 * AccordionItem — a single collapsible section. Carries the bottom rule that
 * separates stacked items; the last item drops its border.
 * ----------------------------------------------------------------------------------------------*/

/** Props accepted by `AccordionItem`. */
export type AccordionItemProps = React.ComponentProps<
  typeof BaseAccordion.Item
>;

/**
 * `AccordionItem` — pairs an `AccordionTrigger` (header) with its
 * `AccordionContent` (panel). Identify it with a unique `value`; pass `disabled`
 * to lock the section. Renders a bottom rule between stacked items.

 *
 * @example
 * <AccordionItem />
 */
export function AccordionItem({
  className,
  ref,
  ...props
}: AccordionItemProps) {
  return (
    <BaseAccordion.Item
      ref={ref}
      data-slot="accordion-item"
      className={cn(
        // `py-1` gives the trigger wash its ≥4px inset from the bottom rule (design.md § Hover
        // geometry) while the header row keeps the height it had.
        "border-b border-border py-1 last:border-b-0",
        className,
      )}
      {...props}
    />
  );
}

/* ------------------------------------------------------------------------------------------------
 * AccordionTrigger — the header button that opens/closes the panel. The trailing
 * chevron rotates 180° when the panel is open via Base UI's `data-panel-open`.
 * ----------------------------------------------------------------------------------------------*/

/** Props accepted by `AccordionTrigger`. */
export type AccordionTriggerProps = React.ComponentProps<
  typeof BaseAccordion.Trigger
>;

/**
 * `AccordionTrigger` — the header button (wrapped in an `AccordionHeader`
 * heading) that toggles its panel. Active state is exposed as `data-panel-open`,
 * which rotates the trailing `ChevronDown` 180°. Compose the label as children.

 *
 * @example
 * <AccordionTrigger />
 */
export function AccordionTrigger({
  className,
  children,
  ref,
  ...props
}: AccordionTriggerProps) {
  return (
    <BaseAccordion.Header data-slot="accordion-header" className="flex">
      <BaseAccordion.Trigger
        ref={ref}
        data-slot="accordion-trigger"
        className={cn(
          "group/accordion-trigger flex flex-1 items-center justify-between gap-4 rounded-md py-2 text-start text-label text-foreground",
          // Underline-on-hover is the LINK affordance and belongs to links only (B7-08). A
          // disclosure hovers with the row wash, which needs the geometry design.md § Hover
          // geometry demands: an inner radius and a ≥4px inset from the item hairline. The
          // trigger supplies both — `px-2` and `rounded-md` here, `py-1` on `AccordionItem` to
          // hold the wash off the bottom rule. That is the migration design.md sanctions: once an
          // ink-signalled control is given padding and an inner radius, it moves to the recipes,
          // both steps together. The padding is POSITIVE, never a negative margin: a wash bled
          // outward past the item's content box overflows the root at 320px. `AccordionContent`
          // carries the same `px-2` so the label stays aligned with the panel body.
          "px-2",
          surfaceInteractive,
          // Base UI surfaces item/root-level `disabled` as a `data-disabled` attribute
          // on the trigger (no native `disabled` attribute), so style both.
          "disabled:pointer-events-none disabled:opacity-(--opacity-dim)",
          "data-disabled:pointer-events-none data-disabled:opacity-(--opacity-dim)",
          "[&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-(--icon-default)",
          className,
        )}
        {...props}
      >
        {children}
        <ChevronDown
          aria-hidden="true"
          className={cn(
            "shrink-0 text-muted-foreground transition-transform duration-fast ease-standard",
            "group-data-[panel-open]/accordion-trigger:rotate-180",
          )}
        />
      </BaseAccordion.Trigger>
    </BaseAccordion.Header>
  );
}

/* ------------------------------------------------------------------------------------------------
 * AccordionContent — the collapsible panel. Height animates from 0 ↔ content
 * height using Base UI's `--accordion-panel-height` CSS var, driven on the
 * `data-starting-style`/`data-ending-style` transition hooks.
 * ----------------------------------------------------------------------------------------------*/

/** Props accepted by `AccordionContent`. */
export type AccordionContentProps = React.ComponentProps<
  typeof BaseAccordion.Panel
>;

/**
 * `AccordionContent` — the collapsible panel (Base UI `Accordion.Panel`) shown
 * when its sibling `AccordionTrigger` is open. Animates its height between `0`
 * and the measured content height via the `--accordion-panel-height` CSS var,
 * transitioning on Base UI's `data-starting-style`/`data-ending-style` hooks.

 *
 * @example
 * <AccordionContent />
 */
export function AccordionContent({
  className,
  children,
  ref,
  ...props
}: AccordionContentProps) {
  return (
    <BaseAccordion.Panel
      ref={ref}
      data-slot="accordion-content"
      className={cn(
        // Height animates the wrapper from 0 → measured height (and back).
        "h-[var(--accordion-panel-height)] overflow-hidden text-base text-muted-foreground",
        "transition-[height] duration-fast ease-standard",
        "data-[starting-style]:h-0 data-[ending-style]:h-0",
        className,
      )}
      {...props}
    >
      {/* Matches the trigger's `px-2` so the panel body lines up under its label. */}
      <div className="px-2 pb-3">{children}</div>
    </BaseAccordion.Panel>
  );
}

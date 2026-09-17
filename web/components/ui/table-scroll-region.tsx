"use client";

import * as React from "react";
import { cn, mergeRefs } from "@vegastack/design";
import { useOverflow } from "@/components/ui/use-overflow";

/** Props for `TableScrollRegion` — the scroll viewport that wraps a `<table>`. */
export interface TableScrollRegionProps extends React.ComponentProps<"div"> {
  /**
   * Accessible name for the scroll region. When present the viewport is exposed
   * as `role="region"` so assistive technology can announce and jump to it; when
   * absent it stays an unnamed focusable container, because an UNNAMED landmark
   * is worse than no landmark and a page showing several tables would otherwise
   * publish several indistinguishable ones.
   * @default undefined
   */
  label?: string;
}

/**
 * `TableScrollRegion` — the horizontally (and optionally vertically) scrollable
 * viewport `Table` wraps its `<table>` in, and the one place the system decides
 * what a scroll viewport owes a keyboard user.
 *
 * A scrollable region that is not focusable can only be scrolled with a pointer
 * (axe `scrollable-region-focusable`). So this measures itself — live, via
 * `useOverflow` — and takes `tabIndex={0}` **only while it actually scrolls**.
 * A table that fits adds no tab stop at all, which is why the measurement exists
 * instead of an unconditional `tabIndex`.
 *
 * The focus outline is pulled INSIDE (`-outline-offset-2`): the viewport clips
 * its own overflow, so an outward outline would be cut off on the scrolling axis.
 * That is the one sanctioned focus deviation (`design.md` § Accessibility).
 *
 * This is the only client leaf in the Table family — every other Table part stays
 * server-safe, which is why it lives in its own file.
 *
 * @example
 * <TableScrollRegion label="Invoices">
 *   <table>…</table>
 * </TableScrollRegion>
 */
export function TableScrollRegion({
  className,
  label,
  ref,
  children,
  "aria-label": ariaLabel,
  ...props
}: TableScrollRegionProps) {
  const [node, setNode] = React.useState<HTMLDivElement | null>(null);
  const scrollable = useOverflow(node, { axis: "either" });

  // The measured node and any consumer ref must be the SAME element, so one callback ref feeds
  // both rather than the component owning one of them. `mergeRefs` is the ONE implementation of
  // that fan-out (`@vegastack/design`); branching on the ref's own callable-ness here would be the
  // tenth copy of a thing that already exists, and `design-lint`'s `hand-rolled-ref-merge` rule now
  // rejects it. `mergeRefs` is not memoized, so the call is wrapped.
  const setRefs = React.useMemo(() => mergeRefs(setNode, ref), [ref]);

  const name = label ?? ariaLabel;

  return (
    <div
      {...props}
      ref={setRefs}
      // Identity AFTER the spread — consumer props must not be able to overwrite
      // the slot every selector and generated surface keys on.
      data-slot="table-container"
      data-scrollable={scrollable ? "" : undefined}
      role={name ? "region" : undefined}
      aria-label={name}
      tabIndex={scrollable ? 0 : undefined}
      className={cn(
        "relative w-full overflow-x-auto focus-visible:-outline-offset-2",
        className,
      )}
    >
      {children}
    </div>
  );
}

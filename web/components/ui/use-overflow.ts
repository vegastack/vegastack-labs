"use client";

import * as React from "react";

/**
 * Which axis (or axes) an overflow measurement compares.
 *
 * - `inline` — `scrollWidth` vs `clientWidth`; the truncating-text and
 *   horizontal-scroll case.
 * - `block` — `scrollHeight` vs `clientHeight`; the line-clamp case.
 * - `either` — overflowing on EITHER axis; what a scroll viewport needs, because
 *   a region that scrolls vertically must be keyboard-reachable just as much as
 *   one that scrolls horizontally.
 */
export type OverflowAxis = "inline" | "block" | "either";

/** Options accepted by `useOverflow`. */
export interface UseOverflowOptions {
  /**
   * Axis to compare.
   * @default "inline"
   */
  axis?: OverflowAxis;
  /**
   * Freeze the last measured value instead of re-observing. Used by disclosures
   * that REMOVE the clamp while expanded — measuring then would report "not
   * overflowing" and immediately re-collapse the disclosure.
   * @default false
   */
  paused?: boolean;
  /**
   * Extra values that should force a re-measure when they change (e.g. the text
   * being rendered). The element and content boxes are observed already; this is
   * only for content changes that move neither box.
   * @default []
   */
  deps?: React.DependencyList;
}

/**
 * `useOverflow` — report whether `node` is currently overflowing along `axis`.
 *
 * The system's ONE overflow measurement. It backs three different jobs that all
 * asked the same question separately before: whether truncated text is actually
 * clipped (so the reveal affordance is offered only when it means something),
 * whether a scroll viewport is actually scrollable (so `tabIndex` is added only
 * when there is something to scroll — an unconditional tab stop on a table that
 * fits is a dead stop for every keyboard user), and whether a clamped block is
 * taller than its clamp.
 *
 * Measurement is live: a `ResizeObserver` watches the element AND its element
 * children, so it tracks both the viewport resizing and its CONTENT growing —
 * a table that gets wider inside a fixed-width container never resizes the
 * container, so observing the container alone would miss it.
 *
 * SSR-safe: the first render always returns `false` and the real value lands in
 * a client-only effect, so a server render never claims content is clipped.
 *
 * @example
 * const [node, setNode] = React.useState<HTMLDivElement | null>(null);
 * const scrollable = useOverflow(node, { axis: "either" });
 * return <div ref={setNode} tabIndex={scrollable ? 0 : undefined} className="overflow-auto">…</div>;
 */
export function useOverflow(
  node: HTMLElement | null,
  { axis = "inline", paused = false, deps = [] }: UseOverflowOptions = {},
): boolean {
  const [overflowing, setOverflowing] = React.useState(false);

  React.useEffect(() => {
    if (!node || paused) return;
    const measure = () => {
      // The +1 slack absorbs sub-pixel layout rounding: a fractional scroll size
      // one hair over the client size is not overflow, and without the slack the
      // observer can oscillate between the two values forever.
      const inline = node.scrollWidth > node.clientWidth + 1;
      const block = node.scrollHeight > node.clientHeight + 1;
      const next =
        axis === "block" ? block : axis === "either" ? inline || block : inline;
      setOverflowing((previous) => (previous === next ? previous : next));
    };
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(node);
    for (const child of node.children) observer.observe(child);
    return () => observer.disconnect();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [node, axis, paused, ...deps]);

  return overflowing;
}

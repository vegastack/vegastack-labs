import * as React from "react";
import { cn } from "@vegastack/design";
import { Marker, MarkerContent } from "@/components/ui/marker";

/* ---
`Timeline` is rail geometry only — deliberately. The audit that commissioned it was
unambiguous: `Item` (+ ItemMedia/ItemContent/ItemTitle/ItemDescription/ItemActions),
`Marker variant="separator"`, `RelativeTime`, and `Avatar` already cover everything a
timeline ROW needs, and duplicating their anatomy here would fork the `data-slot`
vocabulary in two. What no existing part draws is the continuous vertical connector
with a node aligned to each row — so that is all this file adds.

Deliberately NOT done here:
- No TimelineTitle / TimelineDescription / TimelineMedia. Rows are `Item` parts;
  a second title/description vocabulary would compete with the one that exists.
- No live-feed mechanics. A bottom-pinned, prepend-on-scroll-up feed is
  `MessageScroller`; a chronological record is static. Long lists get browser-level
  render skipping via the two-class `content-visibility` recipe MessageScrollerItem
  established — zero dependency, no virtualizer.
- No day-grouping logic. Grouping by calendar day (and the midnight rollover) is host
  data work; `TimelineSeparator` renders the header the host computed.
- No `render` polymorphism on the structural parts. They are `<ol>`/`<li>` shells (the
  Card/Empty precedent — presentational shells never had `render`); the interactive
  surface inside a row is `Item render={<a/>}`.

The whole family is server-safe: no hooks, no 'use client'.
--- */

/** Props accepted by `Timeline`. */
export interface TimelineProps extends React.ComponentPropsWithRef<"ol"> {
  /**
   * Accessible name for the timeline list.
   * @default undefined
   */
  "aria-label"?: string;
}

/**
 * `Timeline` — the chronological record's list root (`<ol>`, newest wherever
 * your data puts it; the component imposes no order). Children are
 * {@link TimelineItem} rows and {@link TimelineSeparator} headers.
 *
 * @example
 * <Timeline aria-label="Activity">
 *   <TimelineSeparator>Today</TimelineSeparator>
 *   <TimelineItem node={<StatusIcon status="done" size="sm" label="" />}>
 *     <Item size="sm">
 *       <ItemContent>
 *         <ItemTitle>Priya closed the deal</ItemTitle>
 *         <ItemDescription>Acme renewal · $12,400</ItemDescription>
 *       </ItemContent>
 *       <ItemContent className="text-sm text-muted-foreground">
 *         <RelativeTime date={closedAt} refresh={false} now={now} />
 *       </ItemContent>
 *     </Item>
 *   </TimelineItem>
 * </Timeline>
 */
export function Timeline({ className, ref, ...props }: TimelineProps) {
  return (
    <ol
      ref={ref}
      data-slot="timeline"
      className={cn("flex list-none flex-col", className)}
      {...props}
    />
  );
}

/** Props accepted by `TimelineItem`. */
export interface TimelineItemProps extends React.ComponentPropsWithRef<"li"> {
  /**
   * The rail node for this entry — a `StatusIcon`, an `Avatar`, or any small
   * glyph. Defaults to a neutral dot. Purely decorative: the entry's meaning
   * must live in its content, so the node column is `aria-hidden`.

   * @default undefined
   */
  node?: React.ReactNode;
}

/**
 * `TimelineItem` — one entry: the rail node + connector on the start side, the
 * row content (compose `Item` parts) beside it. The row needs no ARIA plumbing: the `<li>` is
 * already the list item, and an `Item` outside an `ItemGroup` renders with no role, so nothing
 * can nest listitem-in-listitem. The connector is drawn from
 * this node down to the next entry and hidden on the last one, giving the
 * first/last half-rails for free. Long lists skip offscreen rendering via
 * `content-visibility` (the `MessageScrollerItem` recipe — no dependency).
 *
 * @example
 * <TimelineItem node={<Avatar size="xs" src={actor.avatar} alt="" />}>
 *   <Item size="sm">…</Item>
 * </TimelineItem>
 */
export function TimelineItem({
  className,
  node,
  children,
  ref,
  ...props
}: TimelineItemProps) {
  return (
    <li
      ref={ref}
      data-slot="timeline-item"
      className={cn(
        "group/timeline-item relative flex min-w-0 gap-3",
        // The row is an Item COMPOSED INTO rail geometry: its standalone row
        // padding would detach the text from the node (px) and stack onto the
        // timeline's own rhythm (py), and its centered cross-axis would float
        // trailing meta against a two-line stack — flatten both so the rail
        // owns alignment and spacing.
        "[&_[data-slot=timeline-content]>[data-slot=item]]:items-start [&_[data-slot=timeline-content]>[data-slot=item]]:p-0",
        // Browser-level render skipping for long feeds (MessageScrollerItem's
        // two-class recipe, verbatim).
        "[contain-intrinsic-size:auto_calc(var(--spacing)*24)] [content-visibility:auto]",
        className,
      )}
      {...props}
    >
      {/* Rail column — decorative geometry only; meaning lives in the content. */}
      <span
        aria-hidden
        data-slot="timeline-rail"
        className="flex w-(--icon-default) shrink-0 flex-col items-center gap-1"
      >
        {/* h-5 = the title's leading-snug first-line box: every node shape —
            dot, status icon, avatar — centers on the row's first text line. */}
        <span
          data-slot="timeline-node"
          className="flex h-5 shrink-0 items-center justify-center"
        >
          {node ?? <span className="size-2 rounded-full bg-border" />}
        </span>
        <span
          data-slot="timeline-connector"
          className="w-px flex-1 bg-border group-last/timeline-item:hidden"
        />
      </span>
      {/* `group-last/timeline-item:pb-1` — NOT `pb-0`. The `<li>` above sets
          `content-visibility: auto`, which brings PAINT containment with it, so
          anything a child paints outside this box is clipped and stops being
          hit-testable. A trailing `RelativeTime` expands its pointer target with
          `before:-inset-y-1` (4px), and on the LAST row `pb-0` put that overhang
          outside the clip: measured 2026-09-09, the probe point 1.0px below the
          row resolved to the page wrapper and the effective target collapsed to
          the row's own 23px, under the 24px floor. 4px of padding is the exact
          depth of that hit area, and it restores ownership (0 of 5 points
          missed). Shrinking it back to 0 reopens the defect. */}
      <div
        data-slot="timeline-content"
        className="flex min-w-0 flex-1 flex-col pb-5 group-last/timeline-item:pb-1"
      >
        {children}
      </div>
    </li>
  );
}

/** Props accepted by `TimelineSeparator`. */
export interface TimelineSeparatorProps extends React.ComponentPropsWithRef<"li"> {}

/**
 * `TimelineSeparator` — a labelled divider between groups of entries
 * ("Today", "Last week"), rendered through `Marker variant="separator"` — its
 * own documented use. It is a real `<li>`: an `<ol>` may only contain
 * list items (axe enforces this; a presentation-role child fails
 * `aria-required-children`), and a dated group header reading as one entry of
 * the record is the standard timeline pattern. Wrap the children in a real
 * heading element when the group label should join the page outline.
 *
 * @example
 * <TimelineSeparator>
 *   <h3 className="text-label-sm">Today</h3>
 * </TimelineSeparator>
 */
export function TimelineSeparator({
  className,
  children,
  ref,
  ...props
}: TimelineSeparatorProps) {
  return (
    <li
      ref={ref}
      data-slot="timeline-separator"
      className={cn("pb-4 not-first:pt-2", className)}
      {...props}
    >
      <Marker variant="separator">
        <MarkerContent>{children}</MarkerContent>
      </Marker>
    </li>
  );
}

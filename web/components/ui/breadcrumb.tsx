"use client";

import * as React from "react";
import { useRender } from "@base-ui/react/use-render";
import { ChevronRight, MoreHorizontal } from "lucide-react";
import { cn } from "@vegastack/design";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

/** Props accepted by `Breadcrumb`. */
export type BreadcrumbProps = React.ComponentPropsWithRef<"nav">;

/**
 * `Breadcrumb` — the navigation landmark for a hierarchical trail. Renders a
 * `<nav aria-label="breadcrumb">`. `BreadcrumbLink` uses Base UI `useRender`
 * composition for router links, so the module keeps a client boundary even
 * though the DOM it emits is presentational. Compose with `BreadcrumbList`,
 * `BreadcrumbItem`, `BreadcrumbLink`, `BreadcrumbPage`, `BreadcrumbSeparator`,
 * and `BreadcrumbEllipsis`.
 *
 * @example
 * <Breadcrumb>
 *   <BreadcrumbList>
 *     <BreadcrumbItem>
 *       <BreadcrumbLink href="/">Home</BreadcrumbLink>
 *     </BreadcrumbItem>
 *     <BreadcrumbSeparator />
 *     <BreadcrumbItem>
 *       <BreadcrumbPage>Settings</BreadcrumbPage>
 *     </BreadcrumbItem>
 *   </BreadcrumbList>
 * </Breadcrumb>
 */
function Breadcrumb({ className, ...props }: BreadcrumbProps) {
  return (
    <nav
      aria-label="breadcrumb"
      data-slot="breadcrumb"
      className={className}
      {...props}
    />
  );
}

/** Props accepted by `BreadcrumbList`. */
export type BreadcrumbListProps = React.ComponentPropsWithRef<"ol">;

/**
 * `BreadcrumbList` — the ordered list (`<ol>`) holding the trail's items and
 * separators. Muted, wrapping, and flex-aligned.

 *
 * @example
 * <BreadcrumbList />
 */
function BreadcrumbList({ className, ...props }: BreadcrumbListProps) {
  return (
    <ol
      data-slot="breadcrumb-list"
      className={cn(
        "flex flex-wrap items-center gap-1.5 text-base break-words text-muted-foreground",
        className,
      )}
      {...props}
    />
  );
}

/** Props accepted by `BreadcrumbItem`. */
export type BreadcrumbItemProps = React.ComponentPropsWithRef<"li">;

/** `BreadcrumbItem` — a single trail segment (`<li>`) wrapping a link or page.
 *
 * @example
 * <BreadcrumbItem />
 */
function BreadcrumbItem({ className, ...props }: BreadcrumbItemProps) {
  return (
    <li
      data-slot="breadcrumb-item"
      className={cn("inline-flex items-center gap-1.5", className)}
      {...props}
    />
  );
}

/** Props accepted by `BreadcrumbLink`. */
export interface BreadcrumbLinkProps extends React.ComponentPropsWithRef<"a"> {
  /**
   * Replace the rendered `<a>` element via Base UI `render` composition. Pass a
   * routing link element (e.g. `<NextLink href="/x" />`) or a render function to
   * integrate with a router while keeping breadcrumb styling.

   * @default undefined
   */
  render?: useRender.RenderProp;
}

/**
 * `BreadcrumbLink` — a navigable trail segment. Renders an `<a>` by default and
 * supports the Base UI `render` prop for client-side routing.

 *
 * @example
 * <BreadcrumbLink />
 */
function BreadcrumbLink({
  className,
  render,
  ref,
  ...props
}: BreadcrumbLinkProps) {
  return useRender({
    render: render ?? <a />,
    defaultTagName: "a",
    ref, // forward the consumer ref onto the rendered (or composed) element
    props: {
      "data-slot": "breadcrumb-link",
      className: cn(
        "inline-flex min-h-(--size-xs) min-w-(--size-xs) items-center justify-center rounded-sm hover:text-foreground",
        className,
      ),
      ...props,
    },
  });
}

/** Props accepted by `BreadcrumbPage`. */
export type BreadcrumbPageProps = React.ComponentPropsWithRef<"span">;

/**
 * `BreadcrumbPage` — the current page (the last, non-navigable segment).
 * Exposed to assistive tech via `aria-current="page"`.

 *
 * @example
 * <BreadcrumbPage />
 */
function BreadcrumbPage({ className, ...props }: BreadcrumbPageProps) {
  return (
    <span
      data-slot="breadcrumb-page"
      role="link"
      aria-disabled="true"
      aria-current="page"
      className={cn("font-normal text-foreground", className)}
      {...props}
    />
  );
}

/** Props accepted by `BreadcrumbSeparator`. */
export type BreadcrumbSeparatorProps = React.ComponentPropsWithRef<"li">;

/**
 * `BreadcrumbSeparator` — the visual divider between items. Defaults to a
 * `lucide-react` chevron and is `aria-hidden` (decorative only). Pass `children`
 * to use a custom separator (e.g. a slash).

 *
 * @example
 * <BreadcrumbSeparator />
 */
function BreadcrumbSeparator({
  children,
  className,
  ...props
}: BreadcrumbSeparatorProps) {
  return (
    <li
      data-slot="breadcrumb-separator"
      role="presentation"
      aria-hidden="true"
      className={cn(
        "[&>svg]:size-(--icon-inline) text-muted-foreground-faint",
        className,
      )}
      {...props}
    >
      {children ?? <ChevronRight />}
    </li>
  );
}

/** Props accepted by `BreadcrumbEllipsis`. */
export type BreadcrumbEllipsisProps = React.ComponentPropsWithRef<"span">;

/**
 * `BreadcrumbEllipsis` — a collapsed-segments indicator (`…`) for long trails.
 * Decorative only: expose hidden segments with a separate accessible menu/trigger
 * when users need to navigate them. Place inside a `BreadcrumbItem`.

 *
 * @example
 * <BreadcrumbEllipsis />
 */
function BreadcrumbEllipsis({ className, ...props }: BreadcrumbEllipsisProps) {
  return (
    <span
      data-slot="breadcrumb-ellipsis"
      role="presentation"
      aria-hidden="true"
      className={cn(
        "flex size-5 items-center justify-center [&>svg]:size-(--icon-default)",
        className,
      )}
      {...props}
    >
      <MoreHorizontal />
    </span>
  );
}

/**
 * One hidden segment passed to {@link BreadcrumbCollapsed} or {@link BreadcrumbTrail}.
 * Renders as a real link (`<a href>`, or a `render`-composed router link) — never a
 * JS-only click handler — so collapsed segments keep working with middle-click,
 * "open in new tab", and crawlers.
 */
export interface BreadcrumbSegment {
  /** React key, when the array index isn't stable enough (e.g. reordering). */
  key?: React.Key;
  /** The segment's visible label. */
  label: React.ReactNode;
  /** Href for a plain `<a>` link. Omit and pass `render` for router composition instead. */
  href?: string;
  /**
   * Replace the rendered link element via Base UI `render` composition (e.g. a
   * `NextLink`). Takes precedence over `href` when both are set.
   *
   * Typed `<any>` (not the default `Record<string, unknown>` state) so the same
   * segment feeds either {@link BreadcrumbLink}'s `render` (no state) or
   * `DropdownMenuItem`'s `render` (a `{ disabled, highlighted }` state) inside
   * {@link BreadcrumbCollapsed} — the two Base UI callback shapes are otherwise
   * not mutually assignable.
   */
  render?: useRender.RenderProp<any>;
}

/** Props accepted by `BreadcrumbCollapsed`. */
export interface BreadcrumbCollapsedProps extends Omit<
  React.ComponentPropsWithRef<"button">,
  "children"
> {
  /** The hidden middle segments, revealed as real links inside a menu. */
  items: BreadcrumbSegment[];
  /**
   * Accessible name for the menu trigger — the collapsed run has no visible
   * text of its own, so this is what assistive tech announces.
   * @default 'Show hidden breadcrumbs'
   */
  label?: string;
}

/**
 * `BreadcrumbCollapsed` — a real, navigable stand-in for a run of collapsed
 * middle segments. Pairs the decorative {@link BreadcrumbEllipsis} glyph with a
 * `DropdownMenu` trigger so the hidden segments stay reachable by keyboard and
 * assistive tech — an `aria-label`'d button, never a bare, inert `…`. Each
 * item renders as a real link (`<a href>`, or a `render`-composed router link)
 * inside the menu. Place it inside a `BreadcrumbItem`, where the hidden run
 * would otherwise sit.
 *
 * Building the trail from a flat array? Prefer {@link BreadcrumbTrail}'s
 * `maxItems` prop — it wires this up for you.
 *
 * @example
 * <BreadcrumbItem>
 *   <BreadcrumbCollapsed
 *     items={[
 *       { label: 'Workspace', href: '/w' },
 *       { label: 'Projects', href: '/w/p' },
 *     ]}
 *   />
 * </BreadcrumbItem>
 */
function BreadcrumbCollapsed({
  items,
  label = "Show hidden breadcrumbs",
  className,
  ref,
  ...props
}: BreadcrumbCollapsedProps) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        ref={ref}
        aria-label={label}
        data-slot="breadcrumb-collapsed-trigger"
        className={cn(
          "rounded-sm  hover:text-foreground focus-visible:outline-ring",
          className,
        )}
        {...props}
      >
        <BreadcrumbEllipsis />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start">
        {items.map((item, index) => (
          <DropdownMenuItem
            key={item.key ?? index}
            render={item.render ?? <a href={item.href} />}
          >
            {item.label}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

/** Props accepted by `BreadcrumbTrail`. */
export interface BreadcrumbTrailProps extends Omit<
  BreadcrumbListProps,
  "children"
> {
  /**
   * The full trail, first to last. Every item renders as a `BreadcrumbLink`
   * except the last, which always renders as the current, non-navigable
   * `BreadcrumbPage` — matching the manual composition pattern above.
   */
  items: BreadcrumbSegment[];
  /**
   * Collapse the middle of the trail once `items.length` exceeds this count:
   * the first item and the last `itemsAfterCollapse` items stay visible, and
   * everything between collapses behind a {@link BreadcrumbCollapsed} menu.
   * Omit (default) to never collapse — the list falls back to
   * `BreadcrumbList`'s `flex-wrap`, same as manual composition.
   *
   * Purely a function of `items.length`, so it is SSR-safe and deterministic
   * on first paint — no measurement, no post-hydration re-flow. A
   * width-driven dynamic collapse (mirroring `TruncatedText`'s
   * `ResizeObserver` measurer) was evaluated and deliberately deferred; see
   * the component doc.

   * @default undefined
   */
  maxItems?: number;
  /**
   * How many trailing items (counting the current page) stay visible when
   * `maxItems` triggers a collapse. Only read while collapsing.
   * @default 1
   */
  itemsAfterCollapse?: number;
  /** Accessible name for the collapsed-segments menu trigger.
   * @default undefined
   */
  collapsedLabel?: string;
}

/**
 * `BreadcrumbTrail` — the primary, SSR-safe ergonomic API for a long trail:
 * pass the full `items` array and an optional `maxItems`, and the middle
 * collapses behind {@link BreadcrumbCollapsed} automatically (the first item
 * and the last `itemsAfterCollapse` items always stay visible). Renders a
 * `BreadcrumbList` — place it directly inside `Breadcrumb`.
 *
 * **Static, not measured.** Collapsing is computed from `items.length` alone
 * — no `ResizeObserver`. This was a deliberate choice over a width-driven
 * dynamic measurer (the pattern `TruncatedText` uses): a live measurer for a
 * *set of items* (not a single text node) needs a resize-and-recompute loop
 * that tries collapse states until one fits, which risks visible layout
 * thrash and SSR/hydration mismatches for a component that sits at the very
 * top of the page. An honest, deterministic `maxItems` beats a flaky
 * measurer; pass a smaller `maxItems` at your narrowest breakpoint (e.g. via
 * a container query className) if you need the trail to shrink responsively.
 * Omit `maxItems` and the list keeps its old `flex-wrap` fallback.
 *
 * @example
 * <Breadcrumb>
 *   <BreadcrumbTrail
 *     items={[
 *       { label: 'Home', href: '/' },
 *       { label: 'Workspace', href: '/w' },
 *       { label: 'Projects', href: '/w/p' },
 *       { label: 'Settings', href: '/w/p/settings' },
 *       { label: 'Billing' },
 *     ]}
 *     maxItems={4}
 *   />
 * </Breadcrumb>
 */
function BreadcrumbTrail({
  items,
  maxItems,
  itemsAfterCollapse = 1,
  collapsedLabel,
  className,
  ...props
}: BreadcrumbTrailProps) {
  const lastIndex = items.length - 1;
  const tailCount = Math.max(1, itemsAfterCollapse);
  const shouldCollapse =
    typeof maxItems === "number" && items.length > maxItems;
  const tailStart = shouldCollapse ? Math.max(1, items.length - tailCount) : 1;
  const collapsedItems = shouldCollapse ? items.slice(1, tailStart) : [];

  const nodes: React.ReactNode[] = [];
  items.forEach((item, index) => {
    // The collapsed run occupies indices [1, tailStart) — emit its separator + trigger
    // once, at the run's first index, then skip the rest of the run.
    if (collapsedItems.length > 0 && index > 0 && index < tailStart) {
      if (index === 1) {
        nodes.push(
          <BreadcrumbSeparator key="breadcrumb-trail-collapsed-separator" />,
        );
        nodes.push(
          <BreadcrumbItem key="breadcrumb-trail-collapsed">
            <BreadcrumbCollapsed
              items={collapsedItems}
              label={collapsedLabel}
            />
          </BreadcrumbItem>,
        );
      }
      return;
    }
    if (index > 0) {
      nodes.push(
        <BreadcrumbSeparator
          key={`breadcrumb-trail-separator-${String(item.key ?? index)}`}
        />,
      );
    }
    nodes.push(
      <BreadcrumbItem key={item.key ?? index}>
        {index === lastIndex ? (
          <BreadcrumbPage>{item.label}</BreadcrumbPage>
        ) : (
          <BreadcrumbLink href={item.href} render={item.render}>
            {item.label}
          </BreadcrumbLink>
        )}
      </BreadcrumbItem>,
    );
  });

  return (
    <BreadcrumbList className={className} {...props}>
      {nodes}
    </BreadcrumbList>
  );
}

export {
  Breadcrumb,
  BreadcrumbList,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbPage,
  BreadcrumbSeparator,
  BreadcrumbEllipsis,
  BreadcrumbCollapsed,
  BreadcrumbTrail,
};

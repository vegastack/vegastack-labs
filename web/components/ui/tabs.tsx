"use client";

import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { Tabs as BaseTabs } from "@base-ui/react/tabs";
import { cn, selectedChipVariants } from "@vegastack/design";

/* ------------------------------------------------------------------------------------------------
 * Tabs (Root) — groups the list and the panels, owns orientation.
 * ----------------------------------------------------------------------------------------------*/

/** Props accepted by `Tabs`. */
export interface TabsProps extends React.ComponentProps<typeof BaseTabs.Root> {
  /**
   * Layout flow direction. `horizontal` lays the tab row above the panels;
   * `vertical` stacks the tab list beside the panels.
   * @default 'horizontal'
   */
  orientation?: "horizontal" | "vertical";
}

/**
 * `Tabs` — the root that groups a `TabsList` with its `TabsContent` panels and
 * owns the `orientation`. Flat, shadcn-style API over Base UI Tabs:
 * `Tabs` → `TabsList` → `TabsTrigger` + `TabsContent`.
 *
 * @example
 * <Tabs defaultValue="overview">
 *   <TabsList variant="line">
 *     <TabsTrigger value="overview">Overview</TabsTrigger>
 *     <TabsTrigger value="activity" count={3}>Activity</TabsTrigger>
 *   </TabsList>
 *   <TabsContent value="overview">…</TabsContent>
 *   <TabsContent value="activity">…</TabsContent>
 * </Tabs>
 */
export function Tabs({
  className,
  orientation = "horizontal",
  ref,
  ...props
}: TabsProps) {
  return (
    <BaseTabs.Root
      ref={ref}
      data-slot="tabs"
      orientation={orientation}
      className={cn(
        "group/tabs flex gap-4 data-[orientation=horizontal]:flex-col data-[orientation=vertical]:flex-row",
        className,
      )}
      {...props}
    />
  );
}

/* ------------------------------------------------------------------------------------------------
 * TabsList — the row/column of triggers. `variant` drives the active treatment:
 *   - line: transparent track with a moving underline `Indicator`.
 *   - pill: muted track; the active trigger raises on the shared selected-chip recipe.
 * ----------------------------------------------------------------------------------------------*/

export const tabsListVariants = cva(
  // Horizontal lists scroll instead of overflowing the viewport when the tab row is wider than
  // its container (labels are whitespace-nowrap); max-w-full keeps the scroll region inside the
  // parent rather than growing past it. scroll-fade-x (the CSS-only edge-fade utility from
  // @vegastack/design-tokens/utilities.css, same family message-scroller uses) masks the clipped edge
  // so a partially-hidden last tab reads as "more tabs this way" instead of a hard cut — the
  // fade only appears on the edge that actually has off-screen content (scroll-driven
  // animation, zero JS).
  "group/tabs-list relative inline-flex items-center group-data-[orientation=horizontal]/tabs:max-w-full group-data-[orientation=horizontal]/tabs:overflow-x-auto group-data-[orientation=horizontal]/tabs:scroll-fade-x group-data-[orientation=horizontal]/tabs:scrollbar-none group-data-[orientation=vertical]/tabs:flex-col group-data-[orientation=vertical]/tabs:items-stretch",
  {
    variants: {
      variant: {
        line: cn(
          "gap-1 bg-transparent",
          // bottom rule the underline indicator rides along (horizontal)…
          "group-data-[orientation=horizontal]/tabs:border-b group-data-[orientation=horizontal]/tabs:border-border",
          // …or an inline-start rule (vertical), mirrored in RTL.
          "group-data-[orientation=vertical]/tabs:border-s group-data-[orientation=vertical]/tabs:border-border",
        ),
        pill: cn(
          "gap-1 rounded-lg p-1 text-muted-foreground group-data-[orientation=vertical]/tabs:w-fit",
          selectedChipVariants.track,
        ),
        /** Free-standing chip tabs (Wave 2 — the record-page treatment): no track;
         * the active trigger raises on the shared selected-chip recipe. */
        chip: "gap-1 bg-transparent group-data-[orientation=vertical]/tabs:w-fit",
      },
    },
    defaultVariants: { variant: "line" },
  },
);

/**
 * Carries the list's `variant` down to each trigger. The geometry rides the list's `data-variant`
 * through `group-data-*`, but the SELECTED-state recipe cannot: it is one opaque literal exported
 * by `@vegastack/design` (Tailwind v4's scanner only sees literals, so the string can neither be
 * built up nor variant-prefixed here), which means the trigger has to pick it in JS.
 */
const TabsListContext = React.createContext<"line" | "pill" | "chip">("line");

/** Props accepted by `TabsList`. */
export interface TabsListProps
  extends
    React.ComponentProps<typeof BaseTabs.List>,
    VariantProps<typeof tabsListVariants> {
  /**
   * Active-tab treatment.
   * - `line`: transparent track with a moving underline indicator (default).
   * - `pill`: muted track; the active tab raises on the shared selected-chip
   *   recipe (`selectedChipVariants`) it holds in common with `Segmented`.
   * - `chip`: the same raised chip free-standing, with no track (the dense
   *   record-page treatment).
   * @default 'line'
   */
  variant?: "line" | "pill" | "chip";
}

/**
 * `TabsList` — groups the `TabsTrigger`s. For the `line` variant it also hosts
 * the moving `TabsIndicator`; the `pill` variant styles the active trigger
 * directly. Carries `data-variant` so triggers can react via `group` selectors.

 *
 * @example
 * <TabsList />
 */
export function TabsList({
  className,
  variant = "line",
  children,
  ref,
  ...props
}: TabsListProps) {
  return (
    <BaseTabs.List
      ref={ref}
      data-slot="tabs-list"
      data-variant={variant}
      className={cn(tabsListVariants({ variant }), className)}
      {...props}
    >
      <TabsListContext.Provider value={variant}>
        {children}
      </TabsListContext.Provider>
      {variant === "line" ? (
        <BaseTabs.Indicator
          data-slot="tabs-indicator"
          // Rides the active tab via Base UI's --active-tab-* CSS vars (positions
          // are token-driven, not hardcoded). Underline on the bottom rule for
          // horizontal, on the inline-start rule for vertical.
          className={cn(
            // The active-tab underline is `primary` (the selected-state ink).
            "absolute bg-primary transition-[inset-inline-start,top,width,height] duration-fast ease-standard",
            // Sits flush on the list rule. Horizontal uses `bottom-0` (NOT a negative `-bottom-px`)
            // on purpose: the list is a horizontal scroll container (`overflow-x-auto`), and per the
            // CSS overflow spec an `auto` x-axis promotes the `visible` y-axis to `auto` too — so a
            // 1px negative offset would spill 1px below the box and leave the strip scrollable
            // vertically by that sliver even when every tab fits (the scrollbar is hidden by
            // `scrollbar-none`, so it reads as a phantom "still scrolls a bit"). `bottom-0` keeps the
            // 2px underline fully inside the box, so a fitting tab row has no scrollable overflow at all.
            // `--active-tab-left`/`--active-tab-right` are PHYSICAL distances (from the container's
            // left / right edge), but `start-*` is LOGICAL. In LTR start==left so the left var is
            // correct; in RTL start==right, where the left distance puts the underline under the
            // wrong tab — so RTL is fed Base UI's matching `--active-tab-right`.
            "group-data-[orientation=horizontal]/tabs:bottom-0 group-data-[orientation=horizontal]/tabs:start-[var(--active-tab-left)] rtl:group-data-[orientation=horizontal]/tabs:start-[var(--active-tab-right)] group-data-[orientation=horizontal]/tabs:h-0.5 group-data-[orientation=horizontal]/tabs:w-[var(--active-tab-width)]",
            "group-data-[orientation=vertical]/tabs:-start-px group-data-[orientation=vertical]/tabs:top-[var(--active-tab-top)] group-data-[orientation=vertical]/tabs:h-[var(--active-tab-height)] group-data-[orientation=vertical]/tabs:w-0.5",
          )}
        />
      ) : null}
    </BaseTabs.List>
  );
}

/* ------------------------------------------------------------------------------------------------
 * TabsTrigger — an individual tab button. Active styling keys off Base UI's
 * `data-active`, scoped per-variant via the list's `group-data-[variant=…]`.
 * Supports a leading icon (composed as children) + a trailing `count` badge.
 * ----------------------------------------------------------------------------------------------*/

/** Props accepted by `TabsTrigger`. */
export interface TabsTriggerProps extends React.ComponentProps<
  typeof BaseTabs.Tab
> {
  /**
   * Optional count rendered as a trailing badge — e.g. unread or item totals.
   * Painted as body ink on a quiet ink wash, so it reads on every variant and state.

   * @default undefined
   */
  count?: number;
}

/**
 * `TabsTrigger` — a single tab button (Base UI `Tabs.Tab`). Active state is
 * exposed as `data-active` and styled per the parent list's `variant`. Compose a
 * leading icon as the first child (`<TabsTrigger value="x"><Icon />Label</…>`)
 * and pass `count` for a trailing badge.

 *
 * @example
 * <TabsTrigger />
 */
export function TabsTrigger({
  className,
  count,
  children,
  ref,
  ...props
}: TabsTriggerProps) {
  const variant = React.useContext(TabsListContext);
  return (
    <BaseTabs.Tab
      ref={ref}
      data-slot="tabs-trigger"
      className={cn(
        // Shared chrome.
        "relative inline-flex items-center justify-center gap-1.5 whitespace-nowrap text-label text-muted-foreground focus-visible:-outline-offset-2 select-none",
        "hover:text-foreground data-[active]:text-foreground",
        // Base UI's Tabs.Tab is `focusableWhenDisabled` (no native `disabled` attribute —
        // disabled state is surfaced as `data-disabled`/`aria-disabled`), so style `data-disabled`;
        // the native variant is kept for a consumer-rendered plain button via `render`.
        "disabled:pointer-events-none disabled:opacity-(--opacity-dim)",
        "data-disabled:pointer-events-none data-disabled:opacity-(--opacity-dim)",
        "[&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-(--icon-default)",
        // line: sized on the 32px control scale; active colour only (the moving Indicator paints
        // the primary underline). The wash is held OFF the list rule — a hover fill that runs flush
        // into a container hairline reads as a rendering bug, not a state (design.md §Hover
        // geometry, SP-02). A logical margin does it with no pseudo-element and no stacking
        // games: 4px below the trigger for the horizontal bottom rail, 4px inside the
        // inline-start rail for the vertical one (which mirrors itself in RTL). The Indicator is
        // positioned against the LIST, so it stays welded to the rule either way.
        "group-data-[variant=line]/tabs-list:h-(--size-md) group-data-[variant=line]/tabs-list:rounded-md group-data-[variant=line]/tabs-list:px-3",
        "group-data-[orientation=horizontal]/tabs:group-data-[variant=line]/tabs-list:mb-1",
        "group-data-[orientation=vertical]/tabs:group-data-[variant=line]/tabs-list:ms-1",
        "group-data-[variant=line]/tabs-list:hover:bg-surface-2 group-data-[variant=line]/tabs-list:active:bg-surface-3",
        "group-data-[orientation=vertical]/tabs:group-data-[variant=line]/tabs-list:justify-start",
        // pill + chip: geometry only on the 32px / 28px scales — the LOOK is the one shared
        // raised-chip recipe below (B6-02), which both variants take verbatim so a pill tab, a chip
        // tab, a Segmented chip and a pressed Toggle can never drift into four selected looks again.
        "group-data-[variant=pill]/tabs-list:h-(--size-md) group-data-[variant=pill]/tabs-list:rounded-md group-data-[variant=pill]/tabs-list:px-3",
        "group-data-[orientation=vertical]/tabs:group-data-[variant=pill]/tabs-list:justify-start",
        "group-data-[variant=chip]/tabs-list:h-(--size-sm) group-data-[variant=chip]/tabs-list:rounded-md group-data-[variant=chip]/tabs-list:px-2.5 group-data-[variant=chip]/tabs-list:text-label-sm",
        "group-data-[orientation=vertical]/tabs:group-data-[variant=chip]/tabs-list:justify-start",
        // The recipe reserves its hairline transparently, so selecting a tab adds no layout shift.
        variant !== "line" &&
          cn(selectedChipVariants.item, selectedChipVariants.active),
        className,
      )}
      {...props}
    >
      {children}
      {count != null ? (
        <span
          data-slot="tabs-trigger-count"
          className={cn(
            // The count sits one rung above WHATEVER the trigger currently paints (rest, hover,
            // pressed, active chip) — the alpha twin of the ladder does that in one class, on
            // every variant now that the selected chip is itself an ink tint rather than a
            // translucent `background` plate that needed its own counter-tint.
            //
            // The ink is `foreground`, NOT `muted-foreground`, and that is a contrast fact rather
            // than a taste call. On a `pill`/`chip` list this badge STACKS its wash on the
            // trigger's own: an unselected trigger sits on the `surface-1` track and a selected
            // one adds `--alpha-ink-tint`, so the badge's backdrop is two washes deep. Measured
            // dark (axe, compiled tokens): muted ink read 4.05:1 unselected and 3.43:1 selected —
            // both under AA, and the second is the appearance probe's serious `color-contrast` on
            // /docs/components/tabs. Body ink clears every one of those stacks with room to spare
            // (7.28:1 at the worst, dark selected-hovered over the track). The badge stays
            // visually quiet through its size and its fill, not by thinning ink that is already
            // sitting on a tinted plate.
            // Pinned by `test/contrast.browser.test.tsx` ("Tabs count badge", both themes).
            "ms-0.5 inline-flex min-w-4 items-center justify-center rounded-full bg-foreground/(--alpha-hover) px-1 text-label-sm tabular-nums text-foreground",
          )}
        >
          {count}
        </span>
      ) : null}
    </BaseTabs.Tab>
  );
}

/* ------------------------------------------------------------------------------------------------
 * TabsContent — the panel shown for the active tab.
 * ----------------------------------------------------------------------------------------------*/

/** Props accepted by `TabsContent`. */
export type TabsContentProps = React.ComponentProps<typeof BaseTabs.Panel>;

/**
 * `TabsContent` — the panel (Base UI `Tabs.Panel`) shown when its sibling
 * `TabsTrigger` of the same `value` is active. Keeps a `:focus-visible` ring for
 * keyboard users who tab into the panel.

 *
 * @example
 * <TabsContent />
 */
export function TabsContent({ className, ref, ...props }: TabsContentProps) {
  return (
    <BaseTabs.Panel
      ref={ref}
      data-slot="tabs-content"
      // The focus ring is the GLOBAL `:focus-visible` rule; restating it here (B6-10) only invited
      // the two to drift.
      className={cn("flex-1 text-base", className)}
      {...props}
    />
  );
}

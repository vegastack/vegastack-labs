"use client";

import * as React from "react";
import { Tooltip as BaseTooltip } from "@base-ui/react/tooltip";
import { cn, FLOATING } from "@vegastack/design";
import { Kbd } from "@/components/ui/kbd";
import {
  FloatingArrow,
  FloatingSurface,
} from "@/components/ui/floating-surface";

/**
 * `TooltipProvider` — shares a single open/close delay across every tooltip in
 * a region. Once one tooltip opens, adjacent tooltips open instantly (skip
 * delay). Re-exported from Base UI's `Tooltip.Provider`.
 *
 * Mount it ONCE near the app root — in VegaStack apps it already lives inside
 * `VegaStackProvider`, so you rarely render it yourself. It is exported here for
 * standalone/test setups that need their own provider scope.
 */
export const TooltipProvider = BaseTooltip.Provider;

/**
 * `Tooltip` — the root that groups the trigger and content. Renders no DOM of
 * its own. Wraps Base UI's `Tooltip.Root`.
 *
 * Requires a `TooltipProvider` ancestor (already mounted in `VegaStackProvider`).
 *
 * **Hover/focus-only by design — no touch trigger.** Base UI's `Tooltip` opens on
 * `pointerenter`/`focus` and has no touch-tap handling (verified against the
 * upstream implementation); on devices that can't hover (phones/tablets), content
 * that lives *only* inside a tooltip is permanently unreachable. Never make tooltip
 * content essential-only — the trigger's own label/icon must stand on its own, and
 * the tooltip is supplementary. When a tooltip exists specifically to reveal
 * overflow/clipped text, use `TruncatedText`'s tap-to-toggle disclosure pattern
 * (`packages/ui/registry/ui/truncated-text.tsx`) instead: it detects `(hover:
 * none)` and swaps the hover-only tooltip for a tap-driven expand/collapse on
 * touch, while keeping the Tooltip (and its focus trigger) for keyboard/mouse
 * users unchanged.
 */
export interface TooltipProps extends Omit<
  React.ComponentProps<typeof BaseTooltip.Root>,
  "children"
> {
  /**
   * How long to wait before opening, in milliseconds. Forwarded to the trigger.
   * Falls back to the provider's shared delay when omitted.

   * @default undefined
   */
  delay?: number;
  /** The trigger and content parts.
   * @default undefined
   */
  children?: React.ReactNode;
}

/** `Tooltip` root; shares an optional delay with the composed trigger.
 *
 * @example
 * <Tooltip />
 */
export function Tooltip({ children, delay, ...props }: TooltipProps) {
  return (
    <BaseTooltip.Root data-slot="tooltip" {...props}>
      <DelayContext.Provider value={delay}>{children}</DelayContext.Provider>
    </BaseTooltip.Root>
  );
}

// Lets `delay` set on the root flow down to the trigger (where Base UI reads it)
// without forcing consumers to pass it twice.
const DelayContext = React.createContext<number | undefined>(undefined);

/**
 * `TooltipTrigger` — the element the tooltip attaches to. Renders a `<button>`
 * by default; pass `render` to project the tooltip onto your own element
 * (e.g. an icon `Button`). Wraps Base UI's `Tooltip.Trigger`.
 */
export interface TooltipTriggerProps extends React.ComponentProps<
  typeof BaseTooltip.Trigger
> {}

/** `TooltipTrigger` forwards root delay context to Base UI's focus/hover trigger.
 *
 * @example
 * <TooltipTrigger />
 */
export function TooltipTrigger({ delay, ...props }: TooltipTriggerProps) {
  const inheritedDelay = React.useContext(DelayContext);
  return (
    <BaseTooltip.Trigger
      data-slot="tooltip-trigger"
      delay={delay ?? inheritedDelay}
      {...props}
    />
  );
}

/**
 * `TooltipContent` — the floating panel. Bundles Base UI's `Portal` +
 * `Positioner` + `Popup` so consumers render a single part, and can wrap
 * children in an optional Base UI `Viewport`. Themed with the inverted
 * `bg-foreground` / `text-background` surface (no border — the dark fill
 * carries its own separation) and animated in/out via
 * `data-[starting-style]` / `data-[ending-style]`.
 */
export interface TooltipContentProps extends React.ComponentProps<
  typeof BaseTooltip.Popup
> {
  /**
   * Which side of the trigger to place the tooltip on.
   * @default 'top'
   */
  side?: React.ComponentProps<typeof BaseTooltip.Positioner>["side"];
  /**
   * Distance between the trigger and the tooltip, in pixels.
   * @default 8
   */
  sideOffset?: React.ComponentProps<
    typeof BaseTooltip.Positioner
  >["sideOffset"];
  /**
   * Alignment relative to the chosen side.
   * @default 'center'
   */
  align?: React.ComponentProps<typeof BaseTooltip.Positioner>["align"];
  /** Props forwarded to the underlying Base UI `Portal`.
   * @default undefined
   */
  portalProps?: Omit<
    React.ComponentProps<typeof BaseTooltip.Portal>,
    "children"
  >;
  /** Props forwarded to the underlying Base UI `Positioner`.
   * @default undefined
   */
  positionerProps?: Omit<
    React.ComponentProps<typeof BaseTooltip.Positioner>,
    "side" | "sideOffset" | "align" | "children"
  >;
  /** Props forwarded to an optional Base UI `Viewport` that wraps tooltip children.
   * @default undefined
   */
  viewportProps?: Omit<
    React.ComponentProps<typeof BaseTooltip.Viewport>,
    "children"
  >;
  /**
   * Render a directional arrow pointing at the trigger.
   * @default false
   */
  arrow?: boolean;
}

/** `TooltipContent` renders the scoped portaled positioner, popup, and optional viewport.
 *
 * @example
 * <TooltipContent />
 */
export function TooltipContent({
  children,
  side = "top",
  sideOffset = FLOATING.sideOffsetDetached,
  align = "center",
  portalProps,
  positionerProps,
  viewportProps,
  arrow = false,
  ...props
}: TooltipContentProps) {
  return (
    <FloatingSurface
      parts={{
        Portal: BaseTooltip.Portal,
        Positioner: BaseTooltip.Positioner,
        Popup: BaseTooltip.Popup,
        Viewport: BaseTooltip.Viewport,
      }}
      slot="tooltip"
      surface="tooltip"
      // `role="tooltip"` stays explicit. The 2026-09-07 audit's B3-10 asserted Base UI already
      // sets it; verified against the INSTALLED @base-ui/react 1.6.0, it does not — the string
      // "tooltip" appears in no role assignment anywhere in the package, and removing this prop
      // made `getByRole("tooltip")` fail in truncated-text.test.tsx. The finding is rejected.
      positioning={{ side, sideOffset, align }}
      portalProps={portalProps}
      positionerProps={positionerProps}
      viewportProps={viewportProps}
      popupProps={{ role: "tooltip", ...props }}
      arrow={arrow ? <TooltipArrow /> : undefined}
    >
      {children}
    </FloatingSurface>
  );
}

/**
 * `TooltipArrow` — a small triangle anchored to the trigger. Rendered
 * automatically when `TooltipContent` receives `arrow`, or compose it directly.
 * Wraps Base UI's `Tooltip.Arrow`.
 */
export interface TooltipArrowProps extends React.ComponentProps<
  typeof BaseTooltip.Arrow
> {}

/** `TooltipArrow` renders the directional pointer for a tooltip popup.
 *
 * @example
 * <TooltipArrow />
 */
export function TooltipArrow(props: TooltipArrowProps) {
  return (
    <FloatingArrow
      element={BaseTooltip.Arrow}
      slot="tooltip-arrow"
      tone="tooltip"
      {...props}
    />
  );
}

/** Props accepted by `TooltipKbd`. */
export interface TooltipKbdProps extends React.ComponentProps<"span"> {
  /** The shortcut — a string (split per glyph) or explicit key tokens. */
  keys: string | readonly string[];
  /**
   * Platform label mode, forwarded to `Kbd`. Resolve it at the call site with
   * `usePlatform()`; the default matches that hook's SSR fallback.
   * @default 'other'
   */
  os?: "mac" | "other";
}

/**
 * `TooltipKbd` — a keyboard shortcut hint inside a tooltip. Pass a single string
 * (`"⌘K"` is split per character) or an array of key tokens.
 *
 * It renders `Kbd size="xs"` rather than restyling its own `<kbd>`: there is one
 * key chip in the system and this is not a second one (audit B2-07). That also
 * buys it the OS rewrite — a Windows reader sees `Ctrl`, not `⌘`.
 *
 * @example
 * const { os } = usePlatform();
 * <TooltipKbd keys={["⌘", "K"]} os={os === "mac" ? "mac" : "other"} />
 */
export function TooltipKbd({
  keys,
  os = "other",
  className,
  ...props
}: TooltipKbdProps) {
  const tokens = Array.isArray(keys) ? keys : [...(keys as string)];
  return (
    <Kbd
      // Kbd's `keys` form spreads these onto its KbdGroup root, so the documented
      // `data-slot="tooltip-kbd"` hook survives the consolidation.
      data-slot="tooltip-kbd"
      keys={tokens}
      size="xs"
      os={os}
      className={className}
      {...props}
    />
  );
}

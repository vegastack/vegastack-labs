"use client";

import * as React from "react";
import { Tooltip as BaseTooltip } from "@base-ui/react/tooltip";
import { cn, FLOATING } from "@vegastack/design";
import { useInternalThemeScope } from "@vegastack/design/theme-scope";

function mergeStateClassName<State>(
  className: string,
  userClassName: string | ((state: State) => string | undefined) | undefined,
) {
  if (typeof userClassName === "function") {
    return (state: State) => cn(className, userClassName(state));
  }

  return cn(className, userClassName);
}

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
  className,
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
  const themeScope = useInternalThemeScope();
  const { className: positionerClassName, ...positionerPropsRest } =
    positionerProps ?? {};
  const { className: viewportClassName, ...viewportPropsRest } =
    viewportProps ?? {};

  return (
    <BaseTooltip.Portal {...portalProps}>
      <BaseTooltip.Positioner
        {...positionerPropsRest}
        data-slot="tooltip-positioner"
        side={side}
        sideOffset={sideOffset}
        align={align}
        className={mergeStateClassName<BaseTooltip.Positioner.State>(
          cn(themeScope, "z-(--z-overlay)"),
          positionerClassName,
        )}
      >
        <BaseTooltip.Popup
          data-slot="tooltip-content"
          role="tooltip"
          className={cn(
            themeScope,
            "z-(--z-overlay) flex w-fit max-w-xs origin-(--transform-origin) items-center gap-2 rounded-md bg-foreground px-2.5 py-1 text-sm text-background shadow-overlay select-none",
            // Enter/exit transitions driven by Base UI transition data attributes.
            "transition-[transform,scale,opacity] duration-fast ease-standard",
            "data-[starting-style]:scale-95 data-[starting-style]:opacity-0",
            "data-[ending-style]:scale-95 data-[ending-style]:opacity-0",
            "data-[instant]:duration-0",
            className,
          )}
          {...props}
        >
          {arrow ? <TooltipArrow /> : null}
          {viewportProps ? (
            <BaseTooltip.Viewport
              {...viewportPropsRest}
              data-slot="tooltip-viewport"
              className={mergeStateClassName<BaseTooltip.Viewport.State>(
                themeScope ?? "",
                viewportClassName,
              )}
            >
              {children}
            </BaseTooltip.Viewport>
          ) : (
            children
          )}
        </BaseTooltip.Popup>
      </BaseTooltip.Positioner>
    </BaseTooltip.Portal>
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
export function TooltipArrow({ className, ...props }: TooltipArrowProps) {
  return (
    <BaseTooltip.Arrow
      data-slot="tooltip-arrow"
      className={cn(
        "data-[side=bottom]:-top-1 data-[side=top]:-bottom-1 data-[side=left]:-right-1 data-[side=right]:-left-1",
        className,
      )}
      {...props}
    >
      <span className="block size-2 rotate-45 rounded-xs bg-foreground" />
    </BaseTooltip.Arrow>
  );
}

/**
 * `TooltipKbd` — render a keyboard shortcut hint inside a tooltip. Each key is
 * a `<kbd>` styled with `bg-muted` / `text-muted-foreground`. Pass a single
 * string (`"⌘K"` is split per character) or an array of key tokens.
 */
export interface TooltipKbdProps extends React.ComponentProps<"span"> {
  /** The shortcut — a string (split per glyph) or explicit key tokens. */
  keys: string | readonly string[];
}

/** `TooltipKbd` renders a sequence of compact keyboard-key labels.
 *
 * @example
 * <TooltipKbd />
 */
export function TooltipKbd({ keys, className, ...props }: TooltipKbdProps) {
  const tokens = Array.isArray(keys) ? keys : [...(keys as string)];
  return (
    <span
      data-slot="tooltip-kbd"
      className={cn("inline-flex shrink-0 items-center gap-0.5", className)}
      {...props}
    >
      {tokens.map((key, i) => (
        <kbd
          key={`${key}-${i}`}
          className="inline-flex h-4 min-w-4 items-center justify-center rounded border border-border bg-muted px-1 font-mono text-sm leading-none font-medium text-muted-foreground"
        >
          {key}
        </kbd>
      ))}
    </span>
  );
}

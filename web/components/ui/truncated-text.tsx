"use client";

import * as React from "react";
import { cn } from "@vegastack/design";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";

/**
 * Static `line-clamp-*` utilities, keyed by line count. Listing them as literal
 * class names (rather than building `line-clamp-${n}` at runtime) keeps the
 * classes detectable by Tailwind's content scanner and avoids dynamic class
 * generation. `lines={1}` uses `truncate` (single-line ellipsis) instead.
 */
const LINE_CLAMP: Record<number, string> = {
  2: "line-clamp-2",
  3: "line-clamp-3",
  4: "line-clamp-4",
  5: "line-clamp-5",
  6: "line-clamp-6",
};

/**
 * SSR-safe read of the `(hover: none)` media query — true on devices whose primary
 * input cannot hover (touch phones/tablets), false on mouse/trackpad devices and
 * during server rendering (the conservative default: assume hover-capable, so the
 * pre-hydration render keeps the original Tooltip-only behavior).
 */
function getPrefersNoHover(): boolean {
  if (
    typeof window === "undefined" ||
    typeof window.matchMedia !== "function"
  ) {
    return false;
  }
  return window.matchMedia("(hover: none)").matches;
}

/**
 * Tracks whether the primary input can hover, live — re-reads on change (e.g. a
 * mouse is plugged into a tablet mid-session). SSR-safe: the initial render always
 * returns `false` (hover-capable) and the real value lands in a client-only effect.
 */
function usePrefersNoHover(): boolean {
  const [noHover, setNoHover] = React.useState(getPrefersNoHover);

  React.useEffect(() => {
    if (
      typeof window === "undefined" ||
      typeof window.matchMedia !== "function"
    )
      return;
    const mediaQueryList = window.matchMedia("(hover: none)");
    setNoHover(mediaQueryList.matches);
    const onChange = (event: MediaQueryListEvent) => setNoHover(event.matches);
    mediaQueryList.addEventListener("change", onChange);
    return () => mediaQueryList.removeEventListener("change", onChange);
  }, []);

  return noHover;
}

/**
 * Compose two event handlers so neither clobbers the other (internal handler runs
 * first; the consumer's runs after, unless the internal one calls
 * `preventDefault()`). Used to layer the touch-toggle's `onClick`/`onKeyDown`/
 * `onBlur` on top of whatever the consumer passed through `...props`.
 */
function composeHandlers<E extends React.SyntheticEvent>(
  internal: ((event: E) => void) | undefined,
  external: ((event: E) => void) | undefined,
) {
  if (!internal) return external;
  if (!external) return internal;
  return (event: E) => {
    internal(event);
    if (!event.defaultPrevented) external(event);
  };
}

/**
 * Internal: the DOM attributes/handlers that turn truncated text into a tap-to-toggle
 * disclosure on devices that can't hover. Base UI's `Tooltip` is hover/focus-only
 * (verified against its upstream source — it has no touch trigger), so a truncated
 * string would otherwise be permanently unreadable on touch. When `active` (the text
 * is actually truncated AND the device can't hover), a tap toggles `expanded`; a
 * second tap, Escape, or blur re-clamps. Hover-capable devices get `{}` back — the
 * existing Tooltip-only behavior (including the focus-triggered tooltip for keyboard
 * users) is untouched.
 */
function getTouchToggleProps(
  active: boolean,
  expanded: boolean,
  setExpanded: React.Dispatch<React.SetStateAction<boolean>>,
): Pick<
  React.HTMLAttributes<HTMLElement>,
  "role" | "aria-expanded" | "onClick" | "onKeyDown" | "onBlur"
> {
  if (!active) return {};
  return {
    role: "button",
    "aria-expanded": expanded,
    onClick: () => setExpanded((value) => !value),
    onKeyDown: (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        setExpanded((value) => !value);
      } else if (event.key === "Escape") {
        setExpanded(false);
      }
    },
    onBlur: () => setExpanded(false),
  };
}

/** Props accepted by `TruncatedText`. */
export interface TruncatedTextProps extends Omit<
  React.ComponentPropsWithRef<"span">,
  "children"
> {
  /**
   * Number of lines to show before truncating with an ellipsis. `1` truncates
   * to a single line (`truncate`); `>1` clamps to that many lines
   * (`line-clamp-N`, supported up to 6).
   * @default 1
   */
  lines?: number;
  /**
   * The text to display. Truncated to `lines` and, when actually overflowing,
   * surfaced in full via a Tooltip on hover/focus. On devices that can't hover
   * (`(hover: none)`, e.g. touch phones/tablets) the same overflow instead makes
   * the element a tap-to-toggle disclosure — see the component doc.
   */
  children: React.ReactNode;
  /**
   * Which side of the text to place the overflow Tooltip on.
   * @default 'top'
   */
  tooltipSide?: "top" | "right" | "bottom" | "left";
  /**
   * The element to render. Single-line truncation needs a block-level box, so
   * `p` / `div` are also offered alongside the default inline `span`.
   * @default 'span'
   */
  as?: "span" | "p" | "div";
}

/**
 * `TruncatedText` — truncate text to a single line or `N` lines with an
 * ellipsis, and reveal the full text **only when it actually overflows**.
 * Overflow is measured with a `ResizeObserver`, so the disclosure engages
 * exactly when the text is clipped and stays away otherwise.
 *
 * On hover-capable devices, the full text is surfaced in a Tooltip on
 * hover/focus. Base UI's `Tooltip` is hover/focus-only — it has no touch
 * trigger — so on devices that can't hover (`(hover: none)`, e.g. touch
 * phones/tablets) the element instead becomes a tap-to-toggle disclosure: a
 * tap expands the text in place (wrapping instead of clamping), and a second
 * tap, Escape, or blur re-clamps it. Keyboard focus keeps opening the Tooltip
 * exactly as before on every device — the touch fallback only changes what a
 * *tap* does.
 *
 * Purely presentational: it renders the text and, when clipped, the
 * disclosure — nothing else. Width is controlled by the parent (e.g. a
 * constrained cell or a `max-w-*` wrapper); this component only applies the
 * truncation utility.
 *
 * @example
 * // Single-line truncation inside a constrained box
 * <div className="max-w-48">
 *   <TruncatedText>{longTitle}</TruncatedText>
 * </div>
 *
 * // Multi-line (clamp to 2 lines)
 * <TruncatedText lines={2}>{longDescription}</TruncatedText>
 */
export function TruncatedText({
  lines = 1,
  tooltipSide = "top",
  as: Component = "span",
  className,
  children,
  ref,
  ...props
}: TruncatedTextProps) {
  // Track the measured node as STATE (not a ref) so the effect re-runs when the element
  // remounts — e.g. when overflow flips it from a bare element into <TooltipTrigger render=>,
  // React mounts a fresh node; a deps-gated ref effect would keep observing the detached one.
  const [node, setNode] = React.useState<HTMLElement | null>(null);
  const [expanded, setExpanded] = React.useState(false);
  const noHover = usePrefersNoHover();

  // Compose the internal measurement callback ref with the consumer's `ref` so BOTH
  // observe the same rendered element: `setNode` drives the overflow ResizeObserver while
  // the forwarded ref reaches the consumer. Re-created only when the consumer ref changes.
  const setMergedRef = React.useCallback(
    (instance: HTMLElement | null) => {
      setNode(instance);
      if (typeof ref === "function") ref(instance);
      else if (ref) ref.current = instance;
    },
    [ref],
  );

  // Detect whether the text is *actually* clipped (shared measurement — see `useOverflow`):
  // single-line compares scroll/client width, multi-line compares height. Re-measured on
  // mount/remount, on content change, and on every resize. Measurement is PAUSED while
  // `expanded` — expanding removes the clamp, which would otherwise flip this to `false`
  // and immediately re-collapse the disclosure it just opened.
  const isTruncated = useOverflow(node, [children], lines > 1, expanded);
  const touchToggleActive = isTruncated && noHover;
  const touchToggleProps = getTouchToggleProps(
    touchToggleActive,
    expanded,
    setExpanded,
  );

  const text = (
    <Component
      ref={setMergedRef as React.Ref<never>}
      data-slot="truncated-text"
      data-lines={lines}
      // When clipped, the element becomes the Tooltip trigger (hover-capable devices) — it
      // must be focusable so keyboard users can reveal the full text (register P0-04; same
      // pattern as RelativeTime). Stays focusable on touch too, so the tap-toggle below is
      // keyboard-operable as well.
      tabIndex={isTruncated ? 0 : undefined}
      role={touchToggleProps.role}
      aria-expanded={touchToggleProps["aria-expanded"]}
      className={cn(
        expanded
          ? "block break-words whitespace-normal"
          : lines > 1
            ? (LINE_CLAMP[lines] ?? "line-clamp-6")
            : "block truncate",
        // A pseudo-element cannot extend beyond the `overflow-hidden` required
        // by `truncate`, so the focusable single-line box itself owns the 24px
        // target floor. Multiline clamps naturally exceed this minimum.
        "min-h-(--size-xs)",
        className,
      )}
      {...props}
      onClick={composeHandlers(touchToggleProps.onClick, props.onClick)}
      onKeyDown={composeHandlers(touchToggleProps.onKeyDown, props.onKeyDown)}
      onBlur={composeHandlers(touchToggleProps.onBlur, props.onBlur)}
    >
      {children}
    </Component>
  );

  if (!isTruncated) return text;

  // Always keep the Tooltip wrapper mounted, even on no-hover devices — it's what wires up
  // the focus-triggered tooltip for keyboard users (unaffected by touch). On a device that
  // can't hover, the tooltip simply never opens from a tap (Base UI only opens on
  // pointerenter/focus); the tap instead drives the `touchToggleProps` attributes/handlers
  // above, which are additive and never remove the Tooltip.
  return (
    <Tooltip>
      <TooltipTrigger render={text} />
      <TooltipContent side={tooltipSide} className="max-w-xs break-words">
        {children}
      </TooltipContent>
    </Tooltip>
  );
}

/**
 * Internal hook: report whether `node` is overflowing along the relevant axis.
 * Single-line compares scroll/client width; multi-line compares height. Shared
 * by every variant so the measurement (mount/remount + content + resize) stays
 * identical across `TruncatedText`, `IconText`, and `TableCellText`.
 *
 * `paused` (used by the touch tap-to-toggle disclosure) freezes the last
 * measured value instead of re-observing — while a disclosure is expanded, its
 * clamp is removed, which would otherwise flip this to `false` mid-interaction
 * and immediately re-collapse it. Re-measures for real as soon as `paused`
 * clears (i.e. once re-clamped).
 */
function useOverflow(
  node: HTMLElement | null,
  deps: React.DependencyList,
  multiline = false,
  paused = false,
) {
  const [isTruncated, setIsTruncated] = React.useState(false);
  React.useEffect(() => {
    if (!node || paused) return;
    const check = () => {
      const overflowing = multiline
        ? node.scrollHeight > node.clientHeight + 1
        : node.scrollWidth > node.clientWidth + 1;
      setIsTruncated(overflowing);
    };
    check();
    const observer = new ResizeObserver(check);
    observer.observe(node);
    return () => observer.disconnect();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [node, multiline, paused, ...deps]);
  return isTruncated;
}

/** Props accepted by `IconText`. */
export interface IconTextProps extends Omit<
  React.ComponentPropsWithRef<"div">,
  "children"
> {
  /**
   * Leading icon — render an `Icon`/lucide element (kept at its intrinsic size,
   * never shrunk). Tinted with `text-muted-foreground` to sit quietly beside the
   * label; pass your own color via the icon if you need emphasis.
   */
  icon: React.ReactNode;
  /** The label text; truncated and surfaced in full via Tooltip when it overflows. */
  text: string;
  /** Optional trailing element (badge, count, kbd…), pinned and never truncated.
   * @default undefined
   */
  trailing?: React.ReactNode;
  /**
   * Which side to place the overflow Tooltip on.
   * @default 'top'
   */
  tooltipSide?: "top" | "right" | "bottom" | "left";
}

/**
 * `IconText` — an icon + truncating label + optional trailing slot on one line.
 * The icon and trailing slot stay fixed (`shrink-0`); only the label truncates.
 * On hover-capable devices, the full label is revealed in a Tooltip (wrapping
 * the whole row) when it actually overflows; on devices that can't hover, the
 * row becomes a tap-to-toggle disclosure instead (see `TruncatedText` for the
 * full rationale — same touch fallback, same shared measurement). The common
 * shape for sidebar items, file rows, and nav labels.
 *
 * @example
 * <IconText icon={<Icon as={FileText} />} text={fileName} trailing={<Badge>New</Badge>} tooltipSide="right" />
 */
export function IconText({
  icon,
  text,
  trailing,
  tooltipSide = "top",
  className,
  ref,
  ...props
}: IconTextProps) {
  const [node, setNode] = React.useState<HTMLElement | null>(null);
  const [expanded, setExpanded] = React.useState(false);
  const noHover = usePrefersNoHover();
  // Paused while expanded — see `useOverflow`'s doc for why (removing the clamp would
  // otherwise flip `isTruncated` false and immediately re-collapse the disclosure).
  const isTruncated = useOverflow(node, [text], false, expanded);
  const touchToggleActive = isTruncated && noHover;
  const touchToggleProps = getTouchToggleProps(
    touchToggleActive,
    expanded,
    setExpanded,
  );

  const row = (
    <div
      ref={ref}
      data-slot="icon-text"
      // When the label is clipped, the row becomes the Tooltip trigger (hover-capable
      // devices) — keyboard-focusable so the full text is reachable without a pointer
      // (register P0-04). Stays focusable on touch too, for the tap-toggle below.
      tabIndex={isTruncated ? 0 : undefined}
      role={touchToggleProps.role}
      aria-expanded={touchToggleProps["aria-expanded"]}
      className={cn("flex min-w-0 items-center gap-2", className)}
      {...props}
      onClick={composeHandlers(touchToggleProps.onClick, props.onClick)}
      onKeyDown={composeHandlers(touchToggleProps.onKeyDown, props.onKeyDown)}
      onBlur={composeHandlers(touchToggleProps.onBlur, props.onBlur)}
    >
      <span className="shrink-0 text-muted-foreground" aria-hidden="true">
        {icon}
      </span>
      <span
        ref={setNode as React.Ref<never>}
        data-slot="icon-text-label"
        className={cn(
          "min-w-0",
          expanded ? "break-words whitespace-normal" : "truncate",
        )}
      >
        {text}
      </span>
      {trailing != null && <span className="shrink-0">{trailing}</span>}
    </div>
  );

  if (!isTruncated) return row;

  // See `TruncatedText` — the Tooltip wrapper stays mounted for keyboard/focus even on
  // no-hover devices; `touchToggleActive` only adds the tap-toggle attributes/handlers.
  return (
    <Tooltip>
      <TooltipTrigger render={row} />
      <TooltipContent side={tooltipSide} className="max-w-xs break-words">
        {text}
      </TooltipContent>
    </Tooltip>
  );
}

/** Props accepted by `TableCellText`. */
export interface TableCellTextProps {
  /** The cell text; truncated and surfaced in full via Tooltip when it overflows. */
  text: string;
  /**
   * Cell width (match the column header), e.g. `"200px"`. Constrains the box so
   * truncation engages within the column.

   * @default undefined
   */
  width?: string;
  /**
   * Lines before clamping. `1` truncates to a single line; `>1` clamps.
   * @default 1
   */
  lines?: number;
  /**
   * Render in the monospace family at a smaller size — for IDs, paths, and other
   * fixed-width values.
   * @default false
   */
  mono?: boolean;
  /** Extra classes for the text box.
   * @default undefined
   */
  className?: string;
}

/**
 * `TableCellText` — `TruncatedText` tuned for table cells: a `width` that matches
 * the column header so truncation engages predictably, plus an optional
 * monospace mode for IDs/paths. Reuses `TruncatedText`'s overflow measurement and
 * tooltip — no separate logic.
 *
 * @example
 * <TableCell><TableCellText text={space.name} width="200px" /></TableCell>
 * <TableCell><TableCellText text={space.id} mono /></TableCell>
 */
export function TableCellText({
  text,
  width,
  lines = 1,
  mono = false,
  className,
}: TableCellTextProps) {
  // `width` is a runtime consumer value (e.g. `"200px"`), not a token. It's passed as a CSS custom
  // property (`--cell-w`) and consumed by an arbitrary-value class — so the inline style sets ONLY a
  // `--*` variable, never a direct visual property (contract-clean per §7.1). Set only when provided.
  return (
    <TruncatedText
      lines={lines}
      data-slot="table-cell-text"
      className={cn(
        width && "max-w-[var(--cell-w)]",
        mono && "font-mono text-sm",
        className,
      )}
      style={
        width ? ({ ["--cell-w"]: width } as React.CSSProperties) : undefined
      }
    >
      {text}
    </TruncatedText>
  );
}

"use client";

import * as React from "react";
import { cn } from "@vegastack/design";

/* ------------------------------------------------------------------------------------------------
 * AnimatedNumber — a number display that tweens from its previous value to a new one whenever
 * `value` changes (the classic dashboard stat-card counter). Renders statically on mount (no
 * count-up flash, no hydration mismatch) and only animates on SUBSEQUENT value changes.
 *
 * **Mechanism (investigated, chosen with evidence):** a `requestAnimationFrame` tween, not the
 * CSS `@property --n { syntax: '<integer>' }` + `counter()` route. Both were evaluated:
 *   - The CSS route (`@property`-registered custom property, transitioned, rendered via
 *     `counter-reset`/`counter()` generated content) is well supported for `@property` itself in
 *     the installed Playwright Chromium (this repo's VRT browser) and in current Safari
 *     (16.4+); Firefox shipped `@property` later (128, mid-2024) — recent-but-not-universal, and
 *     the actual number would still need to render via CSS `content: counter(n)`.
 *   - That `counter()` requirement is the disqualifying issue, not just an "a11y caveat": this
 *     component's `format` prop takes full `Intl.NumberFormatOptions` (currency symbols, percent,
 *     `notation: 'compact'`, grouping, locale-specific digits/plurals). CSS counters only support
 *     simple numbering *systems* (`decimal`, `cjk-decimal`, …), not arbitrary ICU formatting — so
 *     the CSS route cannot satisfy the formatting requirement at all, independent of its announced
 *     a11y caveats (generated content is inconsistently exposed to screen readers, and the ticking
 *     text can't be cheaply gated to "announce the final value only"). A JS tween sidesteps all of
 *     this: every intermediate frame is produced by the SAME `Intl.NumberFormat` instance used for
 *     the settled value, and the accessible text is a separate, deliberately-updated node (see
 *     below) — not whatever the visual node happens to expose.
 *
 * **Duration + easing come from the motion tokens, read live via `getComputedStyle`** (not
 * hardcoded ms/curves) — `--duration-{fast,base,slow}` and `--motion-ease-standard`, honoring any
 * local override that cascades onto the rendered node (custom properties inherit). This package's
 * fast unit-test harness (`vitest.config.ts`) compiles no Tailwind/token CSS for most files, so
 * `getComputedStyle` legitimately returns `""` there — {@link FALLBACK_DURATION_MS} and
 * {@link FALLBACK_EASE} are the one-time, documented JS fallbacks (mirroring the shipped defaults
 * in `packages/design-tokens/dist/theme.css`) for exactly that case, never a substitute for the real
 * tokens in a themed app.
 *
 * **Reduced motion:** `prefers-reduced-motion: reduce` renders value changes INSTANTLY — no tween,
 * no intermediate frames — via the same SSR-safe `matchMedia` hook used by
 * `truncated-text.tsx`'s `usePrefersNoHover` / `message-scroller.tsx`'s `usePrefersReducedMotion`.
 * ----------------------------------------------------------------------------------------------*/

const FALLBACK_DURATION_MS: Record<"fast" | "base" | "slow", number> = {
  fast: 150,
  base: 200,
  slow: 300,
};

/** Parses a CSS `<time>` value (`"200ms"` / `"0.2s"`) into milliseconds. `null` if unparsable. */
function parseCssDuration(raw: string): number | null {
  const match = /^(-?[\d.]+)(ms|s)?$/.exec(raw.trim());
  if (!match) return null;
  const num = parseFloat(match[1] ?? "");
  if (!Number.isFinite(num)) return null;
  return match[2] === "s" ? num * 1000 : num;
}

/**
 * Reads a motion-duration token's live value (`--duration-fast|base|slow`) off `el` (or
 * `document.documentElement` when `el` isn't mounted yet). Falls back to
 * {@link FALLBACK_DURATION_MS} when the property resolves empty/unparsable.
 */
function readDurationMs(
  el: Element | null,
  token: "fast" | "base" | "slow",
): number {
  const source =
    el ?? (typeof document === "undefined" ? null : document.documentElement);
  if (source && typeof getComputedStyle === "function") {
    const parsed = parseCssDuration(
      getComputedStyle(source).getPropertyValue(`--duration-${token}`),
    );
    if (parsed !== null) return parsed;
  }
  return FALLBACK_DURATION_MS[token];
}

/** Parses a CSS cubic-bezier easing string's four control-point numbers (x1, y1, x2, y2). */
function parseCubicBezierParams(
  raw: string,
): [number, number, number, number] | null {
  const match =
    /cubic-bezier\(\s*([\d.]+)\s*,\s*(-?[\d.]+)\s*,\s*([\d.]+)\s*,\s*(-?[\d.]+)\s*\)/.exec(
      raw,
    );
  if (!match) return null;
  const nums = [match[1], match[2], match[3], match[4]].map((s) =>
    parseFloat(s ?? ""),
  );
  if (nums.some((n) => !Number.isFinite(n))) return null;
  return nums as [number, number, number, number];
}

/**
 * Builds an easing function from a CSS `cubic-bezier(x1,y1,x2,y2)` curve — the same Newton-Raphson
 * solve browsers use to evaluate `transition-timing-function`: given elapsed-time progress `x` ∈
 * [0,1], find the bezier parameter `t` whose X-component equals `x`, then return its Y-component
 * (the eased progress). 8 iterations is comfortably enough precision for a visual tween.
 */
function cubicBezier(
  x1: number,
  y1: number,
  x2: number,
  y2: number,
): (x: number) => number {
  const cx = 3 * x1;
  const bx = 3 * (x2 - x1) - cx;
  const ax = 1 - cx - bx;
  const cy = 3 * y1;
  const by = 3 * (y2 - y1) - cy;
  const ay = 1 - cy - by;
  const sampleX = (t: number) => ((ax * t + bx) * t + cx) * t;
  const sampleY = (t: number) => ((ay * t + by) * t + cy) * t;
  const sampleDerivX = (t: number) => (3 * ax * t + 2 * bx) * t + cx;

  return (x: number) => {
    if (x <= 0) return 0;
    if (x >= 1) return 1;
    let t = x;
    for (let i = 0; i < 8; i++) {
      const dx = sampleX(t) - x;
      const derivative = sampleDerivX(t);
      if (Math.abs(dx) < 1e-4 || Math.abs(derivative) < 1e-6) break;
      t -= dx / derivative;
    }
    return sampleY(t);
  };
}

/** Mirrors `--motion-ease-standard`'s shipped default (`packages/design-tokens/dist/theme.css`). */
const FALLBACK_EASE = cubicBezier(0.2, 0, 0, 1);

/**
 * Reads `--motion-ease-standard`'s live value off `el` (or `document.documentElement`) and
 * returns an easing function for it. Falls back to {@link FALLBACK_EASE} when the property
 * resolves empty/unparsable (see {@link readDurationMs} for when/why that happens).
 */
function readEasing(el: Element | null): (t: number) => number {
  const source =
    el ?? (typeof document === "undefined" ? null : document.documentElement);
  if (source && typeof getComputedStyle === "function") {
    const params = parseCubicBezierParams(
      getComputedStyle(source).getPropertyValue("--motion-ease-standard"),
    );
    if (params) return cubicBezier(...params);
  }
  return FALLBACK_EASE;
}

/**
 * SSR-safe read of the `(prefers-reduced-motion: reduce)` media query. `window`/`matchMedia` are
 * undefined during server rendering, so this returns `false` until the client effect in
 * {@link usePrefersReducedMotion} can check the real value.
 */
function getPrefersReducedMotion(): boolean {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function")
    return false;
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

/**
 * Tracks the user's `prefers-reduced-motion` OS setting, live. SSR-safe: the initial render
 * always returns `false` and the real value lands in a client-only effect, so this never
 * mismatches during hydration. Same pattern as `message-scroller.tsx`'s
 * `usePrefersReducedMotion` / `truncated-text.tsx`'s `usePrefersNoHover`.
 */
function usePrefersReducedMotion(): boolean {
  const [prefersReducedMotion, setPrefersReducedMotion] = React.useState(
    getPrefersReducedMotion,
  );

  React.useEffect(() => {
    if (
      typeof window === "undefined" ||
      typeof window.matchMedia !== "function"
    )
      return;
    const mediaQueryList = window.matchMedia(
      "(prefers-reduced-motion: reduce)",
    );
    setPrefersReducedMotion(mediaQueryList.matches);
    const onChange = (event: MediaQueryListEvent) =>
      setPrefersReducedMotion(event.matches);
    mediaQueryList.addEventListener("change", onChange);
    return () => mediaQueryList.removeEventListener("change", onChange);
  }, []);

  return prefersReducedMotion;
}

/** Props accepted by `AnimatedNumber`. */
export interface AnimatedNumberProps extends Omit<
  React.ComponentPropsWithRef<"span">,
  "children"
> {
  /**
   * The number to display. On mount it renders statically (no animation). On every later change,
   * the displayed value tweens from whatever is currently shown to this new value. Changing it
   * again mid-tween interrupts the current animation and retargets from the in-flight value —
   * it never snaps back to an earlier value first.
   */
  value: number;
  /**
   * `Intl.NumberFormatOptions` used to format both the settled value and every animated
   * intermediate frame — e.g. `{ style: 'currency', currency: 'USD' }` or
   * `{ notation: 'compact' }`. Omit for plain locale-grouped digits.

   * @default undefined
   */
  format?: Intl.NumberFormatOptions;
  /** BCP-47 locale(s) for `Intl.NumberFormat`. Defaults to the runtime locale.
   * @default undefined
   */
  locale?: string | string[];
  /**
   * Tween duration, as a motion-token name (never a raw millisecond value) — resolved from the
   * live `--duration-{fast,base,slow}` CSS custom property at animation start.
   * @default 'base'
   */
  duration?: "fast" | "base" | "slow";
}

/**
 * `AnimatedNumber` — a number display that counts/tweens from its previous value to a new one on
 * every `value` change (dashboard stat-card counters, live metrics). Renders the exact final
 * value statically on mount and on the server (no count-up flash, no hydration mismatch); only
 * later changes animate.
 *
 * The tween is a `requestAnimationFrame` loop (see the component doc above for why, over a CSS
 * `@property`+`counter()` alternative), eased and timed from the motion tokens
 * (`--duration-{fast,base,slow}` / `--motion-ease-standard`), and instant under
 * `prefers-reduced-motion: reduce`. Every frame — intermediate or settled — is produced by the
 * same `Intl.NumberFormat(locale, format)` instance, so currency symbols, percent signs, compact
 * notation, and locale-specific grouping stay correct throughout the animation, not just at rest.
 *
 * Accessibility: the ticking visual text is `aria-hidden` (a rapid stream of announcements would
 * be noise), and a visually-hidden `role="status"` region announces ONLY the settled value, once
 * per tween — never the intermediate frames. Digits use `tabular-nums` so the layout never jitters
 * horizontally as the number of characters changes mid-count.
 *
 * @example
 * // Re-render with a new `value` to trigger the tween.
 * <AnimatedNumber value={revenue} format={{ style: 'currency', currency: 'USD' }} />
 *
 * @example
 * // Compact notation — "1.2K", "3.4M" — animated through every intermediate frame too.
 * <AnimatedNumber value={followerCount} format={{ notation: 'compact' }} />
 */
export function AnimatedNumber({
  value,
  format,
  locale,
  duration = "base",
  className,
  ref,
  ...props
}: AnimatedNumberProps) {
  // Track the measured node as STATE (not a plain ref) so `readDurationMs`/`readEasing` can read
  // live CSS off the actual rendered element (respecting any local token override that cascades
  // onto it) as soon as it exists, and so a consumer-forwarded ref keeps working uniformly.
  const [node, setNode] = React.useState<HTMLElement | null>(null);
  const setMergedRef = React.useCallback(
    (instance: HTMLElement | null) => {
      setNode(instance);
      if (typeof ref === "function") ref(instance);
      else if (ref) ref.current = instance;
    },
    [ref],
  );

  const prefersReducedMotion = usePrefersReducedMotion();

  // The rendered numeric value — seeded with `value` so the FIRST render (server AND client
  // mount) shows the final value statically. Only effects triggered by a LATER `value` change
  // animate it.
  const [displayValue, setDisplayValue] = React.useState(value);
  // The value announced to assistive tech — updated ONLY once a tween settles (or instantly, for
  // reduced motion), never on intermediate frames, so a screen reader hears the destination, not
  // a stream of ticks.
  const [announcedValue, setAnnouncedValue] = React.useState(value);

  // Always mirrors the latest rendered number, including mid-tween — this is what makes
  // interrupting an in-flight animation retarget smoothly (the new tween's "from" is wherever
  // the visual number currently sits) instead of snapping back to the pre-interruption value.
  const displayValueRef = React.useRef(value);
  const rafRef = React.useRef<number | null>(null);
  const mountedRef = React.useRef(false);

  React.useEffect(() => {
    // Skip the mount run — the initial value is already shown statically above.
    if (!mountedRef.current) {
      mountedRef.current = true;
      return;
    }
    const from = displayValueRef.current;
    const to = value;
    if (from === to) return;

    if (prefersReducedMotion) {
      displayValueRef.current = to;
      setDisplayValue(to);
      setAnnouncedValue(to);
      return;
    }

    const durationMs = readDurationMs(node, duration);
    const ease = readEasing(node);
    const start = performance.now();

    const tick = (now: number) => {
      const t = durationMs <= 0 ? 1 : Math.min(1, (now - start) / durationMs);
      const current = from + (to - from) * ease(t);
      displayValueRef.current = current;
      setDisplayValue(current);
      if (t < 1) {
        rafRef.current = requestAnimationFrame(tick);
      } else {
        rafRef.current = null;
        displayValueRef.current = to;
        setDisplayValue(to);
        setAnnouncedValue(to);
      }
    };
    rafRef.current = requestAnimationFrame(tick);

    // Canceled whenever `value` changes again before this tween finishes (React runs this
    // cleanup before the next effect run) — that's the interruption path: the in-flight
    // animation stops wherever it is, and `displayValueRef.current` (read fresh above, not
    // captured stale) becomes the new tween's starting point.
    return () => {
      if (rafRef.current !== null) cancelAnimationFrame(rafRef.current);
    };
    // `node` / `duration` / `prefersReducedMotion` are intentionally read fresh from the render
    // closure rather than listed here: only a `value` change should ever (re)start a tween, and
    // whenever this effect DOES run, the render that triggered it already carries their current
    // values.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value]);

  // Fresh `Intl.NumberFormat` per render — cheap to construct, and guarantees a `format`/`locale`
  // change is honored immediately (including on an in-flight tween's next frame) rather than
  // waiting on a memo key to invalidate.
  const formatter = new Intl.NumberFormat(locale, format);

  return (
    <span
      ref={setMergedRef}
      data-slot="animated-number"
      // Numerals canon: numbers set in mono with tabular figures (consumer
      // `className` can still override via cn/tw-merge).
      className={cn("font-mono tabular-nums", className)}
      {...props}
    >
      <span data-slot="animated-number-value" aria-hidden="true">
        {formatter.format(displayValue)}
      </span>
      <span
        data-slot="animated-number-live"
        role="status"
        aria-live="polite"
        aria-atomic="true"
        className="sr-only"
      >
        {formatter.format(announcedValue)}
      </span>
    </span>
  );
}

"use client";

import * as React from "react";

/* ---
`use-media-query.ts` is the system's ONE `matchMedia` subscription. Before it, five files
each hand-rolled the same `useState(false)` + `useEffect` + `addEventListener('change')`
shape (`animated-number`, `message-scroller`, `particle-field` each defined a private
`usePrefersReducedMotion`; `use-mobile` and `use-platform` were two more copies), and every
one of them shared the same defect: the first render is hard-coded `false`, so a phone gets
the DESKTOP branch of every JS-driven layout until an effect runs, and a user who asked for
reduced motion gets one frame of full motion.

MECHANISM — `useSyncExternalStore`, not `useState` + `useEffect`:
- `getServerSnapshot` runs on the server AND on the client's hydration render, so a caller
  can DECLARE what the server should assume (`serverFallback`) instead of being forced to
  `false`. React re-reads `getSnapshot` immediately after hydration and re-renders if the
  real media query disagrees — that is the sanctioned way to express "this value is
  unknowable on the server", and it is why it does not warn about a hydration mismatch the
  way rendering the real value in the first client pass would.
- The snapshot is a `boolean` — a primitive — so React's "the result of getSnapshot must be
  immutable" caveat is satisfied by construction; there is no cached-object trap here.
- Subscribing through the store (rather than an effect) also means a media change that
  lands BETWEEN render and commit is not missed: React re-reads the snapshot at commit.

Ref: https://react.dev/reference/react/useSyncExternalStore (React 19.2.8, installed).
--- */

/** Options for {@link useMediaQuery}. */
export interface UseMediaQueryOptions {
  /**
   * What the query reports on the server render and on the client's hydration
   * render, before the real `matchMedia` result is read.
   *
   * This is a DESIGN decision, not a technical default: pick the value that
   * makes the server-rendered markup correct for the majority of the traffic
   * that will see it. A layout hook on a mobile-first marketing page should
   * pass `true` for its `max-width` query so a phone never renders the desktop
   * branch first; an app behind a desktop-only login should leave it `false`.
   *
   * @default false
   */
  serverFallback?: boolean;
}

/**
 * `useMediaQuery` — subscribe to a CSS media query and re-render when it flips.
 *
 * SSR-safe by construction: the server render and the client's hydration render both report
 * `serverFallback`; React re-reads the live query immediately after hydration and re-renders
 * if it disagrees. Environments without `matchMedia` (a JSDOM harness, a non-browser runtime)
 * also report `serverFallback` and never subscribe, so the hook degrades instead of throwing.
 *
 * Prefer a CSS media query or a container query when the branch is purely visual — this hook
 * exists for the cases where JavaScript genuinely has to take a different code path (mount a
 * `Sheet` instead of a rail, skip a `requestAnimationFrame` loop entirely).
 *
 * @param query - Any media query string, exactly as CSS would spell it
 *   (`'(max-width: 767px)'`, `'(pointer: coarse)'`).
 *
 * @example
 * // Mount a modal nav instead of a rail below 768px, correct on the server too.
 * const isNarrow = useMediaQuery('(max-width: 767px)', { serverFallback: true });
 *
 * @example
 * // Branch on pointer type
 * const isCoarse = useMediaQuery('(pointer: coarse)');
 */
export function useMediaQuery(
  query: string,
  { serverFallback = false }: UseMediaQueryOptions = {},
): boolean {
  const subscribe = React.useCallback(
    (onStoreChange: () => void) => {
      if (
        typeof window === "undefined" ||
        typeof window.matchMedia !== "function"
      ) {
        return () => {};
      }
      const mediaQueryList = window.matchMedia(query);
      mediaQueryList.addEventListener("change", onStoreChange);
      return () => mediaQueryList.removeEventListener("change", onStoreChange);
    },
    [query],
  );

  const getSnapshot = React.useCallback(() => {
    if (
      typeof window === "undefined" ||
      typeof window.matchMedia !== "function"
    ) {
      return serverFallback;
    }
    return window.matchMedia(query).matches;
  }, [query, serverFallback]);

  const getServerSnapshot = React.useCallback(
    () => serverFallback,
    [serverFallback],
  );

  return React.useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);
}

/**
 * `usePrefersReducedMotion` — whether the user asked the OS to reduce motion.
 *
 * The system-wide reader for `(prefers-reduced-motion: reduce)`, replacing the three private
 * copies that used to live in `animated-number.tsx`, `message-scroller.tsx` and
 * `particle-field.tsx`.
 *
 * `serverFallback` is `false` here on purpose and is NOT configurable: the CSS reset in
 * `packages/design-tokens/src/base.css` already collapses every `motion-*` utility under the
 * media query, so the server-rendered frame is visually correct either way. This hook exists
 * only for motion that CSS cannot express — a `requestAnimationFrame` loop or a JS tween —
 * where the honest server answer is "assume motion, correct on hydration".
 *
 * @example
 * const prefersReducedMotion = usePrefersReducedMotion();
 * if (prefersReducedMotion) { drawStaticFrame(); return; }
 */
export function usePrefersReducedMotion(): boolean {
  return useMediaQuery("(prefers-reduced-motion: reduce)");
}

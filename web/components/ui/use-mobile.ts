"use client";

import * as React from "react";

/**
 * `useIsMobile` — tracks whether the viewport is narrower than `breakpoint`, live (resizes,
 * device rotation, and devtools viewport changes all re-fire it). SSR-safe: the initial
 * render always returns `false` and the real value lands in a client-only effect, exactly
 * like `truncated-text.tsx`'s `usePrefersNoHover` — so server and client markup agree on
 * first paint and React never warns about a hydration mismatch.
 *
 * @param breakpoint - Viewport width (px) at and above which the layout is "desktop". Below
 *   it, `useIsMobile` reports `true`.
 *   @default 768
 *
 * @example
 * // Switch a nav rail into a slide-in Sheet below 768px
 * const isMobile = useIsMobile();
 * return isMobile ? <MobileNav /> : <DesktopNav />;
 *
 * @example
 * // Custom breakpoint
 * const isCompact = useIsMobile(1024);
 */
export function useIsMobile(breakpoint = 768): boolean {
  // The server has no viewport, so both the server render and the client's hydration render must
  // start from the same conservative value. The effect below synchronizes the real media-query
  // result immediately after hydration and then keeps it live.
  const [isMobile, setIsMobile] = React.useState(false);

  React.useEffect(() => {
    if (
      typeof window === "undefined" ||
      typeof window.matchMedia !== "function"
    )
      return;
    const mediaQueryList = window.matchMedia(
      `(max-width: ${breakpoint - 1}px)`,
    );
    setIsMobile(mediaQueryList.matches);
    const onChange = (event: MediaQueryListEvent) => setIsMobile(event.matches);
    mediaQueryList.addEventListener("change", onChange);
    return () => mediaQueryList.removeEventListener("change", onChange);
  }, [breakpoint]);

  return isMobile;
}

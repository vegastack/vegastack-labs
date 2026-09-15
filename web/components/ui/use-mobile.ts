"use client";

// `useIsMobile` is a NAMED viewport query over the system's one matchMedia subscription
// (`use-media-query.ts`). It owns the breakpoint arithmetic and the SSR policy; it owns no
// subscription of its own.
import { useMediaQuery } from "@/components/ui/use-media-query";

/** Options for {@link useIsMobile}. */
export interface UseIsMobileOptions {
  /**
   * What the hook reports on the server render and the client's hydration render.
   * Pass `true` on a mobile-first surface so a phone never paints the desktop branch first.
   * @default false
   */
  serverFallback?: boolean;
}

/**
 * `useIsMobile` — tracks whether the viewport is narrower than `breakpoint`, live (resizes,
 * device rotation, and devtools viewport changes all re-fire it).
 *
 * **SSR:** the server render and the client's hydration render report `serverFallback`, and
 * React reconciles against the real query immediately after hydration. The default is `false`
 * (desktop) because that is the correct assumption for the app shells this hook was written
 * for — but a mobile-first surface should pass `serverFallback: true` rather than accept a
 * first paint of the desktop branch on a phone.
 *
 * Prefer CSS: a Tailwind breakpoint (or a container query, which follows the element's own
 * width rather than the viewport's) handles anything purely visual. Reach for this hook only
 * when JavaScript must take a different path — mounting a modal `Sheet` instead of a rail,
 * enabling pointer drag, choosing a different component tree.
 *
 * @param breakpoint - Viewport width (px) at and above which the layout is "desktop". Below
 *   it, `useIsMobile` reports `true`.
 *   @default 768
 * @param options - SSR policy. @default {}
 *
 * @example
 * // Switch a nav rail into a slide-in Sheet below 768px
 * const isMobile = useIsMobile();
 * return isMobile ? <MobileNav /> : <DesktopNav />;
 *
 * @example
 * // Custom breakpoint
 * const isCompact = useIsMobile(1024);
 *
 * @example
 * // A mobile-first page: render the mobile branch on the server too
 * const isMobile = useIsMobile(768, { serverFallback: true });
 */
export function useIsMobile(
  breakpoint = 768,
  { serverFallback = false }: UseIsMobileOptions = {},
): boolean {
  return useMediaQuery(`(max-width: ${breakpoint - 1}px)`, { serverFallback });
}

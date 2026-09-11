"use client";

// Canonical registry source for the Toaster. The package provider
// (`packages/ui/src/provider/toaster.tsx`) is mirrored from this implementation;
// the registry header stamp is the only intentional difference.

import type { CSSProperties } from "react";
import {
  Toaster as SonnerToaster,
  type ToasterProps as SonnerToasterProps,
} from "sonner";
import { useTheme } from "next-themes";
import { CircleCheck, Info, OctagonX, TriangleAlert } from "lucide-react";
import { cn } from "@vegastack/design";
import { useInternalThemeScope } from "@vegastack/design/theme-scope";

// Sonner (verified against the installed sonner@2.x source, `dist/index.mjs`'s
// `assignOffset()`) writes `offset`/`mobileOffset` straight onto `--offset-{side}` /
// `--mobile-offset-{side}` CSS custom properties on the toaster root — passing an object sets
// ALL FOUR sides (any side you omit falls back to sonner's own default, 24px / 16px on
// mobile), and each value can be a plain CSS string, not just a number. That lets us keep
// sonner's own default spacing (`var(--spacing)*6` = 24px desktop, `var(--spacing)*4` = 16px
// mobile — the same tokens the rest of the registry uses for spacing math, e.g. dialog's
// `max-h-[calc(100dvh-var(--spacing)*8)]`) while adding `env(safe-area-inset-*)` so
// edge-pinned toasts clear the iOS home indicator/notch. `env()` resolves to `0px` on
// non-notched devices, so this is a zero-visual-change default there.
const DEFAULT_OFFSET: NonNullable<SonnerToasterProps["offset"]> = {
  top: "calc(var(--spacing) * 6 + env(safe-area-inset-top))",
  right: "calc(var(--spacing) * 6 + env(safe-area-inset-right))",
  bottom: "calc(var(--spacing) * 6 + env(safe-area-inset-bottom))",
  left: "calc(var(--spacing) * 6 + env(safe-area-inset-left))",
};

const DEFAULT_MOBILE_OFFSET: NonNullable<SonnerToasterProps["mobileOffset"]> = {
  top: "calc(var(--spacing) * 4 + env(safe-area-inset-top))",
  right: "calc(var(--spacing) * 4 + env(safe-area-inset-right))",
  bottom: "calc(var(--spacing) * 4 + env(safe-area-inset-bottom))",
  left: "calc(var(--spacing) * 4 + env(safe-area-inset-left))",
};

/** Props accepted by `Toaster`. */
export interface ToasterProps extends SonnerToasterProps {
  /**
   * Toast stacking edge — `'top-left' | 'top-center' | 'top-right' |
   * 'bottom-left' | 'bottom-center' | 'bottom-right'`.
   * @default 'bottom-right'
   */
  position?: SonnerToasterProps["position"];
  /**
   * Distance from the viewport edge (desktop / `>600px` widths). Defaults to
   * Sonner's own 24px spacing PLUS `env(safe-area-inset-*)` on every side, so
   * edge-pinned toasts clear the iOS home indicator/notch — `env()` resolves to
   * `0px` on non-notched devices, so this is visually identical to Sonner's
   * default there. Pass your own `{ top, right, bottom, left }` (or a single
   * string/number) to override.
   * @default { top: 'calc(var(--spacing)*6 + env(safe-area-inset-top))', ... }
   */
  offset?: SonnerToasterProps["offset"];
  /**
   * Same as {@link offset}, applied at the `≤600px` mobile breakpoint (Sonner's
   * own responsive cutoff). Defaults to Sonner's 16px spacing plus the safe-area
   * inset.
   * @default { top: 'calc(var(--spacing)*4 + env(safe-area-inset-top))', ... }
   */
  mobileOffset?: SonnerToasterProps["mobileOffset"];
  /**
   * Color scheme. Defaults to the resolved `next-themes` value (so the toaster
   * tracks light/dark/system without extra wiring).
   * @default 'system'
   */
  theme?: SonnerToasterProps["theme"];
  /**
   * Show a dismiss X on every toast (top-right). On by default — pass `false`
   * for auto-dismiss-only toasts.
   * @default true
   */
  closeButton?: boolean;
  /**
   * Visually stack toasts on top of each other (expand on hover) instead of
   * laying them out vertically.
   * @default false
   */
  expand?: boolean;
}

/**
 * `Toaster` — VegaStack-configured Sonner toaster. Mount **once** at the app
 * root (it is already bundled into `<VegaStackProvider>`, so most apps never
 * render it directly — they just call {@link toast}).
 *
 * Surface uses semantic tokens — Sonner's own `--normal-bg` / `--normal-text` /
 * `--normal-border` / `--border-radius` vars are wired to `popover` /
 * `popover-foreground` / `border` / `radius-lg`, plus the matching
 * `bg-popover` / `text-popover-foreground` / `border-border` utilities, a
 * `rounded-lg` radius, `p-4` padding, and `shadow-overlay`. The `success` /
 * `error` / `warning` / `info` variants are tinted via per-state `classNames`
 * and carry matching lucide icons. Theme (light/dark/system) follows
 * `next-themes` `useTheme()`.
 *
 * Note (§7.6 ref): this is a mount-once portal toaster — Sonner owns its DOM and
 * drops unknown props (it has no single consumer-referenceable host root), so a
 * forwarded ref is intentionally N/A here (unlike the DOM-root primitives).
 *
 * Safe-area aware by default: {@link ToasterProps.offset} / {@link ToasterProps.mobileOffset}
 * default to Sonner's own spacing plus `env(safe-area-inset-*)`, so edge-pinned toasts clear
 * the iOS home indicator/notch — a no-op on non-notched devices.

 *
 * @example
 * <Toaster />
 */
export function Toaster({
  className,
  toastOptions,
  theme: themeProp,
  offset = DEFAULT_OFFSET,
  mobileOffset = DEFAULT_MOBILE_OFFSET,
  closeButton = true,
  ...props
}: ToasterProps) {
  const { theme = "system" } = useTheme();
  const themeScope = useInternalThemeScope();
  return (
    <SonnerToaster
      // Sonner forwards `className` to its root <ol> but drops unknown props, so
      // the slot/group hook rides on the class (`toaster` is the group anchor the
      // `group-[.toaster]:*` toast classNames below target).
      theme={(themeProp ?? theme) as ToasterProps["theme"]}
      // Toasts are dismissable by default; the X's side is re-pointed to top-RIGHT via the
      // `--toast-close-button-*` vars on each toast's own class (see `classNames.toast`
      // below) — Sonner declares the LTR defaults on `html[dir]`/`[data-sonner-toaster][dir]`
      // with attribute-selector specificity a lone utility class can't beat, but a var
      // declared directly ON the toast element wins over any inherited value.
      closeButton={closeButton}
      className={cn(themeScope, "toaster group", className)}
      offset={offset}
      mobileOffset={mobileOffset}
      // Wire Sonner's own CSS-var API to our semantic tokens so the default toast
      // surface, border, text, and radius track the design system (and theme) —
      // these read on the `[data-sonner-toaster]` root and cascade to each toast.
      // Only `--*` custom properties (no direct visual props), so it stays within
      // the token-only inline-style contract.
      style={
        {
          "--normal-bg": "var(--popover)",
          "--normal-text": "var(--popover-foreground)",
          "--normal-border": "var(--border)",
          "--border-radius": "var(--radius-lg)",
        } as CSSProperties
      }
      icons={{
        success: (
          <CircleCheck
            className="size-(--icon-default) text-success-text"
            aria-hidden
          />
        ),
        info: (
          <Info className="size-(--icon-default) text-info-text" aria-hidden />
        ),
        warning: (
          <TriangleAlert
            className="size-(--icon-default) text-warning-text"
            aria-hidden
          />
        ),
        error: (
          <OctagonX
            className="size-(--icon-default) text-destructive-text"
            aria-hidden
          />
        ),
      }}
      toastOptions={{
        ...toastOptions,
        classNames: {
          // `rounded-lg` (12) + `shadow-overlay` match the overlay surface recipe;
          // `p-4` (16) and `gap-3` set the toast's internal rhythm. Surface/border/
          // text ride the CSS vars above plus the matching semantic utilities.
          toast:
            "group toast gap-3 group-[.toaster]:bg-popover group-[.toaster]:text-popover-foreground group-[.toaster]:border-border group-[.toaster]:rounded-lg group-[.toaster]:p-4 group-[.toaster]:shadow-overlay [--toast-close-button-end:0] [--toast-close-button-start:auto] [--toast-close-button-transform:translate(35%,-35%)]",
          description: "group-[.toast]:text-muted-foreground",
          actionButton:
            "group-[.toast]:bg-primary group-[.toast]:text-primary-foreground",
          cancelButton:
            "group-[.toast]:bg-muted group-[.toast]:text-muted-foreground",
          // The dismiss X: Sonner's default chrome re-tokened to the house surface
          // (its stock styling reads Sonner-internal grays that ignore the theme).
          closeButton:
            "group-[.toast]:border-border group-[.toast]:bg-background group-[.toast]:text-muted-foreground group-[.toast]:hover:bg-muted group-[.toast]:hover:text-foreground",
          success:
            "group-[.toaster]:border-success/(--alpha-border-soft) group-[.toaster]:bg-success-subtle",
          error:
            "group-[.toaster]:border-destructive/(--alpha-border-soft) group-[.toaster]:bg-destructive-subtle",
          warning:
            "group-[.toaster]:border-warning/(--alpha-border-soft) group-[.toaster]:bg-warning-subtle",
          info: "group-[.toaster]:border-info/(--alpha-border-soft) group-[.toaster]:bg-info-subtle",
          ...toastOptions?.classNames,
        },
      }}
      {...props}
    />
  );
}

/**
 * `toast` — imperative API for showing notifications (re-exported from Sonner).
 * Call `toast('Saved')`, `toast.success(...)`, `toast.error(...)`,
 * `toast.warning(...)`, `toast.info(...)`, `toast.promise(...)`, or
 * `toast.dismiss(id)`. Requires a mounted {@link Toaster} (provided by
 * `<VegaStackProvider>`).
 */
export { toast } from "sonner";

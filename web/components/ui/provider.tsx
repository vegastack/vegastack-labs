"use client";

// Canonical registry source for the app-root provider. The package provider
// (`packages/ui/src/provider/vegastack-provider.tsx` + `use-vegastack-theme.ts`) is
// mirrored from this implementation so the private npm build and the registry copy-in
// do not diverge — if they must differ, change ONLY this file and re-mirror there.
// (Same discipline as the Toaster: `registry/ui/sonner.tsx` ↔ `src/provider/toaster.tsx`.)

import * as React from "react";
import { ThemeProvider as NextThemesProvider, useTheme } from "next-themes";
import { Tooltip } from "@base-ui/react/tooltip";
import { DirectionProvider } from "@base-ui/react/direction-provider";
import { Toaster } from "@/components/ui/sonner";

/** Props accepted by `VegaStackProvider`. */
export interface VegaStackProviderProps extends Omit<
  React.ComponentProps<typeof NextThemesProvider>,
  "children"
> {
  /** The application subtree that receives theme, direction, tooltip, and toast context. */
  children: React.ReactNode;
  /** Text direction for Base UI components. @default 'ltr' */
  direction?: "ltr" | "rtl";
  /**
   * Controls the bundled `Toaster`. Mount-once portal toasters must not be
   * double-mounted, so pass `false` if you already render a `<Toaster />`
   * elsewhere, or pass your own element to override the default.
   * @default true
   */
  toaster?: boolean | React.ReactNode;
}

/**
 * `VegaStackProvider` — single root wrapper bundling theme (next-themes),
 * toasts (Sonner), tooltip coordination, and text direction. Wrap your app
 * root with it exactly once; every VegaStack component below it then gets
 * dark mode, working `toast()` calls, shared tooltip delays, and direction
 * context for free.
 *
 * The host `<html>` needs `suppressHydrationWarning` (next-themes mutates it
 * on the client before hydration).
 *
 * The `toaster` prop lets a host suppress (`false`) or replace the bundled
 * `<Toaster />` — necessary because a Sonner toaster is a mount-once portal
 * that must not be mounted twice.
 *
 * @example
 * ```tsx
 * // app/layout.tsx
 * export default function RootLayout({ children }: { children: React.ReactNode }) {
 *   return (
 *     <html lang="en" suppressHydrationWarning>
 *       <body>
 *         <VegaStackProvider>{children}</VegaStackProvider>
 *       </body>
 *     </html>
 *   );
 * }
 * ```
 */
export function VegaStackProvider({
  children,
  direction = "ltr",
  toaster = true,
  ...themeProps
}: VegaStackProviderProps) {
  const toasterNode =
    toaster === true ? <Toaster /> : toaster === false ? null : toaster;
  return (
    <NextThemesProvider
      attribute="class"
      defaultTheme="system"
      enableSystem
      disableTransitionOnChange
      {...themeProps}
    >
      <DirectionProvider direction={direction}>
        <Tooltip.Provider>
          {children}
          {toasterNode}
        </Tooltip.Provider>
      </DirectionProvider>
    </NextThemesProvider>
  );
}

/**
 * `useVegaStackTheme` — thin wrapper over next-themes' `useTheme()`. Returns the
 * resolved theme plus a `setTheme` setter (`'light' | 'dark' | 'system'`). Use it
 * to build a theme toggle anywhere below `VegaStackProvider`.
 *
 * @example
 * ```tsx
 * const { resolvedTheme, setTheme } = useVegaStackTheme();
 * <Button onClick={() => setTheme(resolvedTheme === 'dark' ? 'light' : 'dark')}>
 *   Toggle theme
 * </Button>
 * ```
 */
export function useVegaStackTheme() {
  return useTheme();
}

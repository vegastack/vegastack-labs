"use client";

import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { useRender } from "@base-ui/react/use-render";
import { PanelLeft } from "lucide-react";
import { cn } from "@vegastack/design";
import { Separator } from "@/components/ui/separator";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Skeleton } from "@/components/ui/skeleton";
import { useIsMobile } from "@/components/ui/use-mobile";

/** `document.cookie` key `SidebarProvider` writes on every toggle (see the "Cookie persistence" section below). */
const SIDEBAR_COOKIE_NAME = "sidebar_state";
/** ~1 year, matching the other long-lived first-party cookies in the house pattern. */
const SIDEBAR_COOKIE_MAX_AGE = 60 * 60 * 24 * 365;

interface SidebarContextValue {
  /** `"expanded"` when the rail shows labels, `"collapsed"` when icon-only. Desktop only — the mobile Sheet has no icon-collapsed state, see `openMobile`. */
  state: "expanded" | "collapsed";
  /** Whether the desktop rail is expanded. Irrelevant on mobile — use `openMobile`. */
  open: boolean;
  /** Set the desktop open state (controlled or uncontrolled). */
  setOpen: (open: boolean) => void;
  /**
   * Flip the sidebar open/closed for the CURRENT viewport — toggles `openMobile` when
   * `isMobile`, otherwise `open`. This is what `SidebarTrigger`/`SidebarRail` call; prefer it
   * over `setOpen`/`setOpenMobile` directly unless you specifically need to target one mode.
   */
  toggleSidebar: () => void;
  /** Whether the viewport is below the mobile breakpoint (`SidebarProvider`'s `mobileBreakpoint`, default 768px) — see `use-mobile.ts`. */
  isMobile: boolean;
  /** Whether the mobile Sheet is open. Always `false` on desktop viewports. */
  openMobile: boolean;
  /** Set the mobile Sheet's open state directly. */
  setOpenMobile: (open: boolean) => void;
}

const SidebarContext = React.createContext<SidebarContextValue | null>(null);

/**
 * `useSidebar` — read the sidebar's open/collapsed state (desktop `open`/`state`, mobile
 * `openMobile`/`isMobile`) and toggle it from any descendant (e.g. a custom trigger in a
 * header). Throws if used outside a `SidebarProvider`.
 */
export function useSidebar(): SidebarContextValue {
  const context = React.useContext(SidebarContext);
  if (!context) {
    throw new Error("useSidebar must be used within a SidebarProvider.");
  }
  return context;
}

/** Props accepted by `SidebarProvider`. */
export interface SidebarProviderProps extends React.ComponentProps<"div"> {
  /**
   * Initial open state when uncontrolled.
   * @default true
   */
  defaultOpen?: boolean;
  /** Controlled open state — pair with `onOpenChange`.
   * @default undefined
   */
  open?: boolean;
  /** Called whenever the open state changes (in both modes).
   * @default undefined
   */
  onOpenChange?: (open: boolean) => void;
  /**
   * Keyboard shortcut for toggling the rail. `true` uses `b` with Cmd/Ctrl;
   * pass a single key string to customize, or `false` to disable.
   * @default true
   */
  keyboardShortcut?: boolean | string;
  /**
   * Viewport width (px) below which `Sidebar` switches into the mobile Sheet mode. Forwarded
   * to `useIsMobile`.
   * @default 768
   */
  mobileBreakpoint?: number;
}

/**
 * `SidebarProvider` — owns the expanded/collapsed state and lays out the
 * sidebar next to the page content. Wrap your app shell (sidebar + main) in it.
 * Supports controlled (`open`/`onOpenChange`) and uncontrolled (`defaultOpen`)
 * usage, and registers a <kbd>⌘</kbd>/<kbd>Ctrl</kbd>+<kbd>B</kbd> shortcut to
 * toggle the rail. Also owns `openMobile` (the mobile Sheet's open state) —
 * separate from desktop `open`/`state`, since collapsing to icons and sliding
 * a Sheet in are different interactions that can't share one boolean.
 *
 * **Cookie persistence (SSR-safe pattern):** every desktop toggle writes a
 * `sidebar_state` cookie (`path=/`, ~1yr) so the NEXT page load can restore it
 * without a flash of the wrong state. This component only ever WRITES the
 * cookie, client-side, in response to a user action — it never reads
 * `document.cookie` at render (that would differ between server and client
 * and trigger a hydration mismatch). To restore state across reloads, read the
 * cookie in your server layout and pass it as `defaultOpen`:
 * ```tsx
 * // app/layout.tsx (Server Component)
 * import { cookies } from 'next/headers';
 * const defaultOpen = (await cookies()).get('sidebar_state')?.value !== 'false';
 * <SidebarProvider defaultOpen={defaultOpen}>…</SidebarProvider>
 * ```

 *
 * @example
 * <SidebarProvider />
 */
export function SidebarProvider({
  defaultOpen = true,
  open: openProp,
  onOpenChange,
  keyboardShortcut = true,
  mobileBreakpoint = 768,
  className,
  style,
  children,
  ...props
}: SidebarProviderProps) {
  const isMobile = useIsMobile(mobileBreakpoint);
  const [openMobile, setOpenMobile] = React.useState(false);

  const [openState, setOpenState] = React.useState(defaultOpen);
  const open = openProp ?? openState;

  const setOpen = React.useCallback(
    (value: boolean | ((value: boolean) => boolean)) => {
      const next = typeof value === "function" ? value(open) : value;
      if (openProp === undefined) setOpenState(next);
      onOpenChange?.(next);
      // Write-only, client-side, on toggle — see the SSR-safe cookie pattern documented above.
      if (typeof document !== "undefined") {
        document.cookie = `${SIDEBAR_COOKIE_NAME}=${next}; path=/; max-age=${SIDEBAR_COOKIE_MAX_AGE}`;
      }
    },
    [open, openProp, onOpenChange],
  );

  const toggleSidebar = React.useCallback(
    () => (isMobile ? setOpenMobile((v) => !v) : setOpen((v) => !v)),
    [isMobile, setOpen],
  );

  React.useEffect(() => {
    if (keyboardShortcut === false) return;
    const shortcutKey =
      typeof keyboardShortcut === "string" ? keyboardShortcut : "b";
    const handleKeyDown = (event: KeyboardEvent) => {
      if (
        event.key.toLowerCase() === shortcutKey.toLowerCase() &&
        (event.metaKey || event.ctrlKey)
      ) {
        event.preventDefault();
        toggleSidebar();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [keyboardShortcut, toggleSidebar]);

  const state = open ? "expanded" : "collapsed";

  const contextValue = React.useMemo<SidebarContextValue>(
    () => ({
      state,
      open,
      setOpen,
      toggleSidebar,
      isMobile,
      openMobile,
      setOpenMobile,
    }),
    [state, open, setOpen, toggleSidebar, isMobile, openMobile],
  );

  return (
    <SidebarContext.Provider value={contextValue}>
      <div
        data-slot="sidebar-wrapper"
        // `--sidebar-width` / `--sidebar-width-icon` are design tokens (:root, @vegastack/design-tokens);
        // pass a style override here to re-size a single sidebar instance (register P2-13).
        style={style}
        className={cn("group/sidebar-wrapper flex min-h-svh w-full", className)}
        {...props}
      >
        {children}
      </div>
    </SidebarContext.Provider>
  );
}

/** Props accepted by `Sidebar`. */
export interface SidebarProps extends React.ComponentProps<"nav"> {
  /**
   * Which edge the sidebar sits on. Also controls which edge the mobile Sheet slides in from.
   * @default 'left'
   */
  side?: "left" | "right";
  /**
   * Visual treatment (desktop only — the mobile Sheet always uses its own panel styling).
   * - `sidebar` (default): flush rail, bordered against the page edge.
   * - `floating`: a detached panel — margin on every edge, its own border/radius/shadow.
   * - `inset`: same rail treatment as `sidebar`; pair it with `SidebarInset` on the main
   *   content, which becomes the rounded/bordered/shadowed panel instead.
   * @default 'sidebar'
   */
  variant?: "sidebar" | "floating" | "inset";
  /**
   * How the rail collapses when `state` is `"collapsed"`.
   * - `icon` (default — the pre-existing behavior): shrinks to `--sidebar-width-icon`,
   *   labels hide (`sr-only`, stay in the accessible name).
   * - `offcanvas`: slides fully off-screen (`translate`) and its width drops to 0, so page
   *   content reflows to fill the space.
   * - `none`: never collapses (and never becomes the mobile Sheet) — always renders at
   *   `--sidebar-width`. `SidebarTrigger`/`SidebarRail`/`toggleSidebar` become no-ops for it.
   * @default 'icon'
   */
  collapsible?: "offcanvas" | "icon" | "none";
}

/**
 * `Sidebar` — the navigation rail. Reads the provider's state to animate between the
 * expanded (`--sidebar-width`) and collapsed (`collapsible`-dependent) widths, and — below
 * the mobile breakpoint — swaps to rendering its children inside a `Sheet` instead (focus
 * trap, scroll lock, and Escape-to-close come from `Sheet` for free). In every mode the
 * children still render inside a real `<nav>` landmark (`data-slot="sidebar"`) carrying
 * `data-state`/`data-collapsible`/`data-variant`/`data-side` for descendant styling — so a
 * `ref` on `Sidebar` always resolves to that `<nav>`, regardless of mode. Compose
 * `SidebarHeader` / `SidebarContent` / `SidebarFooter` inside it. Pass an `aria-label` to
 * name the landmark. On desktop the rail is sticky at the viewport's block start: document
 * scrolling moves the adjacent page while the rail remains visible, and overflowing navigation
 * scrolls inside `SidebarContent` so the header/footer stay pinned.

 *
 * @example
 * <Sidebar />
 */
export function Sidebar({
  side = "left",
  variant = "sidebar",
  collapsible = "icon",
  className,
  children,
  ...props
}: SidebarProps) {
  const { state, isMobile, openMobile, setOpenMobile } = useSidebar();

  // `collapsible="none"` is checked FIRST (before the mobile branch): a rail that "never
  // collapses" also never becomes a Sheet — it always renders in place, full size.
  if (collapsible === "none") {
    return (
      <nav
        data-slot="sidebar"
        data-state="expanded"
        data-collapsible="none"
        data-variant={variant}
        data-side={side}
        className={cn(
          "group/sidebar sticky top-0 flex h-svh w-(--sidebar-width) self-start flex-col border-border bg-sidebar text-sidebar-foreground",
          "data-[side=left]:border-r data-[side=right]:order-last data-[side=right]:border-l",
          className,
        )}
        {...props}
      >
        {children}
      </nav>
    );
  }

  if (isMobile) {
    return (
      <Sheet open={openMobile} onOpenChange={setOpenMobile}>
        <SheetContent
          side={side}
          data-slot="sidebar-sheet-content"
          // `--sidebar-width-mobile` mirrors `--sidebar-width`/`--sidebar-width-icon`'s
          // var+arbitrary-class routing, but (unlike those two) it isn't a global design token
          // yet — packages/design-tokens is out of scope for this change (see the summary for the
          // follow-up). The `18rem` fallback lives INSIDE the var() call (an arbitrary-value
          // class, sanctioned by the design-lint arbitrary-value contract), never in a raw
          // style literal, so it stays lint-clean; override it same as the other two, with a
          // `style={{ '--sidebar-width-mobile': '20rem' }}` on `SidebarProvider`.
          className="w-[var(--sidebar-width-mobile,18rem)] max-w-[var(--sidebar-width-mobile,18rem)] gap-0 border-sidebar-border bg-sidebar p-0 text-sidebar-foreground"
        >
          <SheetHeader className="sr-only">
            <SheetTitle>Navigation</SheetTitle>
            <SheetDescription>Site navigation menu</SheetDescription>
          </SheetHeader>
          <nav
            data-slot="sidebar"
            data-state="expanded"
            data-collapsible=""
            data-variant={variant}
            data-side={side}
            data-mobile="true"
            className={cn(
              "group/sidebar relative flex h-full min-h-0 flex-1 flex-col",
              className,
            )}
            {...props}
          >
            {children}
          </nav>
        </SheetContent>
      </Sheet>
    );
  }

  return (
    <nav
      data-slot="sidebar"
      data-state={state}
      data-collapsible={state === "collapsed" ? collapsible : ""}
      data-variant={variant}
      data-side={side}
      className={cn(
        "peer group/sidebar sticky flex h-svh self-start flex-col text-sidebar-foreground transition-[width,transform] duration-base ease-standard",
        "w-(--sidebar-width)",
        collapsible === "icon" &&
          "data-[state=collapsed]:w-(--sidebar-width-icon)",
        collapsible === "offcanvas" &&
          "data-[state=collapsed]:w-0 data-[state=collapsed]:overflow-hidden data-[state=collapsed]:data-[side=left]:-translate-x-full data-[state=collapsed]:data-[side=right]:translate-x-full",
        variant === "floating"
          ? "top-2 m-2 h-[calc(100svh-var(--spacing)*4)] rounded-lg border border-border bg-sidebar shadow-overlay"
          : "top-0 border-border bg-sidebar data-[side=left]:border-r data-[side=right]:order-last data-[side=right]:border-l",
        className,
      )}
      {...props}
    >
      {children}
    </nav>
  );
}

/**
 * `SidebarHeader` — the top region of the rail, typically the app/workspace
 * switcher or logo. Stacks its children with consistent padding.
 */
export interface SidebarHeaderProps extends React.ComponentProps<"div"> {}

/** `SidebarHeader` renders the padded top region of the navigation rail.
 *
 * @example
 * <SidebarHeader />
 */
export function SidebarHeader({ className, ...props }: SidebarHeaderProps) {
  return (
    <div
      data-slot="sidebar-header"
      className={cn(
        "flex shrink-0 flex-col gap-2 p-2 pt-[calc(var(--spacing)*2+env(safe-area-inset-top))]",
        className,
      )}
      {...props}
    />
  );
}

/**
 * `SidebarContent` — the scrollable middle region holding the navigation
 * groups. Grows to fill the available height and hides overflow when collapsed.
 */
export interface SidebarContentProps extends React.ComponentProps<"div"> {}

/** `SidebarContent` renders the rail's flexible scroll container.
 *
 * @example
 * <SidebarContent />
 */
export function SidebarContent({ className, ...props }: SidebarContentProps) {
  return (
    <div
      data-slot="sidebar-content"
      className={cn(
        "flex min-h-0 flex-1 flex-col gap-1 overflow-auto group-data-[state=collapsed]/sidebar:overflow-hidden",
        className,
      )}
      {...props}
    />
  );
}

/**
 * `SidebarFooter` — the bottom region of the rail, typically the user menu or
 * sign-out. Stacks its children with consistent padding.
 */
export interface SidebarFooterProps extends React.ComponentProps<"div"> {}

/** `SidebarFooter` renders the padded bottom region of the navigation rail.
 *
 * @example
 * <SidebarFooter />
 */
export function SidebarFooter({ className, ...props }: SidebarFooterProps) {
  return (
    <div
      data-slot="sidebar-footer"
      className={cn(
        "mt-auto flex shrink-0 flex-col gap-2 p-2 pb-[calc(var(--spacing)*2+env(safe-area-inset-bottom))]",
        className,
      )}
      {...props}
    />
  );
}

/**
 * `SidebarGroup` — a labelled section of menu items inside `SidebarContent`.
 * Pair with `SidebarGroupLabel` and a `SidebarMenu`.
 */
export interface SidebarGroupProps extends React.ComponentProps<"div"> {}

/** `SidebarGroup` groups one labelled set of sidebar destinations.
 *
 * @example
 * <SidebarGroup />
 */
export function SidebarGroup({ className, ...props }: SidebarGroupProps) {
  return (
    <div
      data-slot="sidebar-group"
      className={cn("relative flex w-full min-w-0 flex-col p-2", className)}
      {...props}
    />
  );
}

/**
 * `SidebarGroupLabel` — the heading above a group's items. Fades out and
 * collapses its height when the rail is collapsed to the icon rail.
 */
export interface SidebarGroupLabelProps extends React.ComponentProps<"h3"> {}

/** `SidebarGroupLabel` renders a semantic heading that collapses with the rail.
 *
 * @example
 * <SidebarGroupLabel />
 */
export function SidebarGroupLabel({
  className,
  ...props
}: SidebarGroupLabelProps) {
  return (
    <h3
      data-slot="sidebar-group-label"
      className={cn(
        "flex h-(--size-md) shrink-0 items-center rounded-md px-2 text-label-sm text-muted-foreground transition-[margin,opacity] duration-base ease-standard",
        "group-data-[state=collapsed]/sidebar:-mt-8 group-data-[state=collapsed]/sidebar:opacity-0",
        className,
      )}
      {...props}
    />
  );
}

/**
 * `SidebarMenu` — the `<ul>` that lists `SidebarMenuItem`s within a group.
 */
export interface SidebarMenuProps extends React.ComponentProps<"ul"> {}

/** `SidebarMenu` renders the semantic list that owns sidebar menu items.
 *
 * @example
 * <SidebarMenu />
 */
export function SidebarMenu({ className, ...props }: SidebarMenuProps) {
  return (
    <ul
      data-slot="sidebar-menu"
      className={cn("flex w-full min-w-0 flex-col gap-0.5", className)}
      {...props}
    />
  );
}

/**
 * `SidebarMenuItem` — the `<li>` wrapper for a single navigation entry. Holds a
 * `SidebarMenuButton` (and optionally a badge or action).
 */
export interface SidebarMenuItemProps extends React.ComponentProps<"li"> {}

/** `SidebarMenuItem` renders one semantic list item and its positioned accessories.
 *
 * @example
 * <SidebarMenuItem />
 */
export function SidebarMenuItem({ className, ...props }: SidebarMenuItemProps) {
  return (
    <li
      data-slot="sidebar-menu-item"
      className={cn("group/menu-item relative", className)}
      {...props}
    />
  );
}

/**
 * Menu-button variants. Active state and the leading accent rail are driven by
 * the `data-active` attribute; sizes mirror the rest of the system.
 */
export const sidebarMenuButtonVariants = cva(
  cn(
    "group/menu-button peer/menu-button relative flex w-full items-center gap-2 overflow-hidden rounded-md px-2 text-start text-base transition-[width,height,padding] duration-fast ease-standard select-none",
    "text-sidebar-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground active:bg-sidebar-accent active:text-sidebar-accent-foreground",
    "data-[active=true]:bg-sidebar-accent data-[active=true]:font-medium data-[active=true]:text-sidebar-accent-foreground",
    "disabled:pointer-events-none disabled:opacity-(--opacity-dim) aria-disabled:pointer-events-none aria-disabled:opacity-(--opacity-dim)",
    // Leading active-indicator rail.
    "before:absolute before:top-1 before:bottom-1 before:start-0 before:w-0.5 before:scale-y-0 before:rounded-full before:bg-sidebar-primary before:transition-transform before:duration-fast before:ease-standard data-[active=true]:before:scale-y-100",
    // Collapse to an icon-only square; the label goes visually-hidden (`sr-only`), NOT
    // `display:none`, so it stays in the button's accessible name (register P0-03).
    "group-data-[state=collapsed]/sidebar:justify-center group-data-[state=collapsed]/sidebar:px-0",
    // The label's last-child `<span>` gets a bare single-line `truncate` here (DOM/API stays
    // unchanged — no dependency on `TruncatedText`). For a label that can genuinely run long
    // (user-editable workspace/project names, etc.) and needs the "reveal on hover/tap when it
    // actually overflows" behavior, wrap the span's TEXT content in `TruncatedText` yourself:
    // `<span><TruncatedText>{label}</TruncatedText></span>`. `sidebar.tsx` deliberately does NOT
    // import `truncated-text.tsx` itself — every consumer of this menu button would pay for its
    // ResizeObserver + ARIA disclosure logic even when labels are short static strings (the
    // common case), and it would add a registryDependency (`@vegastack/truncated-text`, which
    // itself pulls in `@vegastack/tooltip`) to every app that installs `sidebar`. Composing it
    // at the call site keeps that weight opt-in.
    "[&>span:last-child]:truncate group-data-[state=collapsed]/sidebar:[&>span:last-child]:sr-only",
    "[&_svg]:size-(--icon-default) [&_svg]:shrink-0",
  ),
  {
    variants: {
      size: {
        default: "h-(--size-md) text-base",
        sm: "h-(--size-sm) text-sm",
        lg: "h-(--size-lg) text-base",
      },
    },
    defaultVariants: { size: "default" },
  },
);

/** Props accepted by `SidebarMenuButton`. */
export interface SidebarMenuButtonProps
  extends
    React.ComponentPropsWithRef<"button">,
    VariantProps<typeof sidebarMenuButtonVariants> {
  /**
   * Replace the rendered element via Base UI `render` composition. Pass an `<a>`
   * for navigation while keeping the styling.

   * @default undefined
   */
  render?: useRender.RenderProp;
  /**
   * Marks the item as the current page — applies the accent background, bold
   * label, and leading rail, and sets `aria-current="page"`.
   * @default false
   */
  isActive?: boolean;
}

/**
 * `SidebarMenuButton` — the interactive row inside a `SidebarMenuItem`. Renders
 * a `<button>` by default; pass `render={<a href="…" />}` for a nav link.
 * Compose an `Icon` plus a `<span>` label as children — the label hides when
 * the rail collapses. Set `isActive` to highlight the current page.
 *
 * The label span truncates to one line by default (bare `truncate`, no dependency wired in).
 * For labels that can genuinely overflow and should reveal their full text on hover/tap, wrap
 * the label in `TruncatedText` at the call site — see `sidebarMenuButtonVariants`' comment for
 * why that composition isn't hard-wired here.

 *
 * @example
 * <SidebarMenuButton />
 */
export function SidebarMenuButton({
  className,
  size = "default",
  isActive = false,
  render,
  ref,
  ...props
}: SidebarMenuButtonProps) {
  return useRender({
    render: render ?? <button />,
    defaultTagName: "button",
    ref, // forward the consumer ref onto the rendered (or composed) element
    props: {
      "data-slot": "sidebar-menu-button",
      "data-size": size,
      "data-active": isActive,
      "aria-current": isActive ? "page" : undefined,
      className: cn(sidebarMenuButtonVariants({ size }), className),
      ...props,
    },
  });
}

/**
 * `SidebarMenuBadge` — a small count/status pill anchored to the inline end of a
 * menu button. In the icon-collapsed rail it becomes a compact status dot while
 * its text stays in the accessibility tree.
 */
export interface SidebarMenuBadgeProps extends React.ComponentProps<"span"> {}

/** `SidebarMenuBadge` renders an inline-end count or status for a menu item.
 *
 * @example
 * <SidebarMenuBadge />
 */
export function SidebarMenuBadge({
  className,
  ...props
}: SidebarMenuBadgeProps) {
  return (
    <span
      data-slot="sidebar-menu-badge"
      className={cn(
        // top-1/2 -translate-y-1/2 vertically centers the badge on its row for EVERY menu-button
        // size (an absolutely-positioned sibling has no static position, so without it the badge
        // rendered below the row).
        "pointer-events-none absolute top-1/2 end-1 flex h-5 min-w-5 -translate-y-1/2 items-center justify-center rounded-md px-1 text-sm font-medium tabular-nums text-sidebar-foreground select-none",
        "peer-data-[active=true]/menu-button:text-sidebar-accent-foreground",
        "group-data-[state=collapsed]/sidebar:top-0.5 group-data-[state=collapsed]/sidebar:end-0.5 group-data-[state=collapsed]/sidebar:size-2 group-data-[state=collapsed]/sidebar:min-w-0 group-data-[state=collapsed]/sidebar:translate-y-0 group-data-[state=collapsed]/sidebar:overflow-hidden group-data-[state=collapsed]/sidebar:rounded-full group-data-[state=collapsed]/sidebar:bg-sidebar-primary group-data-[state=collapsed]/sidebar:p-0 group-data-[state=collapsed]/sidebar:text-transparent",
        className,
      )}
      {...props}
    />
  );
}

/**
 * Fixed, deterministic cycle of text-line widths for `SidebarMenuSkeleton` rows — varied
 * enough that a stack of skeleton rows doesn't read as a single repeated block, but never
 * `Math.random()` (design-lint/VRT determinism: a skeleton must render pixel-identical on
 * every run for visual-regression snapshots to be meaningful).
 */
const SIDEBAR_MENU_SKELETON_WIDTHS = [
  "w-3/5",
  "w-4/5",
  "w-2/3",
  "w-11/12",
  "w-1/2",
] as const;

/** Props accepted by `SidebarMenuSkeleton`. */
export interface SidebarMenuSkeletonProps extends Omit<
  React.ComponentProps<"div">,
  "children"
> {
  /**
   * Show the leading icon-circle placeholder alongside the text line.
   * @default true
   */
  showIcon?: boolean;
  /**
   * This row's position when rendering several skeleton rows in a loop (e.g. the array
   * index). Selects a width from `SIDEBAR_MENU_SKELETON_WIDTHS` deterministically (`index %
   * length`), so consecutive rows vary in width without any randomness.
   * @default 0
   */
  index?: number;
}

/**
 * `SidebarMenuSkeleton` — a loading placeholder shaped like a `SidebarMenuButton`: an
 * icon-circle plus a text-line, composing `Skeleton`. Render one per expected menu item while
 * data loads; pass each row's `index` so the text-line widths vary (deterministically — see
 * `SIDEBAR_MENU_SKELETON_WIDTHS`) instead of every row rendering the identical width.
 *
 * @example
 * <SidebarMenu>
 *   {Array.from({ length: 5 }, (_, i) => (
 *     <SidebarMenuItem key={i}>
 *       <SidebarMenuSkeleton index={i} />
 *     </SidebarMenuItem>
 *   ))}
 * </SidebarMenu>
 */
export function SidebarMenuSkeleton({
  className,
  showIcon = true,
  index = 0,
  ...props
}: SidebarMenuSkeletonProps) {
  const normalizedIndex =
    ((index % SIDEBAR_MENU_SKELETON_WIDTHS.length) +
      SIDEBAR_MENU_SKELETON_WIDTHS.length) %
    SIDEBAR_MENU_SKELETON_WIDTHS.length;
  const widthClass = SIDEBAR_MENU_SKELETON_WIDTHS[normalizedIndex];
  return (
    <div
      data-slot="sidebar-menu-skeleton"
      className={cn(
        "flex h-(--size-md) items-center gap-2 rounded-md px-2",
        className,
      )}
      {...props}
    >
      {showIcon ? (
        <Skeleton shape="circle" className="size-(--icon-default) shrink-0" />
      ) : null}
      <Skeleton shape="line" className={cn("h-4 flex-1", widthClass)} />
    </div>
  );
}

/**
 * `SidebarSeparator` — a thin rule between groups, inset to match the rail
 * padding.
 */
export interface SidebarSeparatorProps extends React.ComponentProps<
  typeof Separator
> {}

/** `SidebarSeparator` renders the inset rule between adjacent navigation groups.
 *
 * @example
 * <SidebarSeparator />
 */
export function SidebarSeparator({
  className,
  ...props
}: SidebarSeparatorProps) {
  return (
    <Separator
      data-slot="sidebar-separator"
      className={cn("mx-2 my-0 w-auto bg-sidebar-border", className)}
      {...props}
    />
  );
}

/** Props accepted by `SidebarTrigger`. */
export interface SidebarTriggerProps extends React.ComponentPropsWithRef<"button"> {
  /** Replace the rendered element (Base UI composition).
   * @default undefined
   */
  render?: useRender.RenderProp;
}

/**
 * `SidebarTrigger` — a button that toggles the rail (or, below the mobile breakpoint, the
 * Sheet) between open and closed. Renders a `PanelLeft` icon with an accessible label; place
 * it in the page header or the sidebar header.
 *
 * The visible box is `size-(--size-sm)` (28px) — below the WCAG 2.5.8 24×24 CSS px minimum
 * target on its own once you count typical adjacent spacing, and well short of the ~44px
 * comfortable mobile target where this button doubles as the Sheet's open control. Like
 * `checkbox.tsx`'s size variants, it adds an invisible `::before` hit-area expansion
 * (`relative` + `before:absolute before:-inset-2`, transparent generated content) that
 * brings the EFFECTIVE hit area to 28 + 2×8 = 44px without touching the visible icon box —
 * satisfying the ≥44px mobile target and the ≥24px desktop minimum with the same, simpler,
 * non-breakpoint-conditional expansion.

 *
 * @example
 * <SidebarTrigger />
 */
export function SidebarTrigger({
  className,
  onClick,
  render,
  ref,
  ...props
}: SidebarTriggerProps) {
  const { toggleSidebar } = useSidebar();
  return useRender({
    render: render ?? <button />,
    defaultTagName: "button",
    ref, // forward the consumer ref onto the rendered (or composed) element
    props: {
      type: "button",
      "data-slot": "sidebar-trigger",
      "aria-label": "Toggle sidebar",
      onClick: (event: React.MouseEvent<HTMLButtonElement>) => {
        onClick?.(event);
        toggleSidebar();
      },
      className: cn(
        "relative inline-flex size-(--size-sm) shrink-0 items-center justify-center rounded-md text-sidebar-foreground  before:absolute before:-inset-2 hover:bg-sidebar-accent hover:text-sidebar-accent-foreground [&_svg]:size-(--icon-default) [&_svg]:shrink-0",
        className,
      ),
      children: <PanelLeft aria-hidden />,
      ...props,
    },
  });
}

/** Props accepted by `SidebarRail`. */
export interface SidebarRailProps extends React.ComponentProps<"button"> {}

/**
 * `SidebarRail` — a thin invisible strip along the sidebar's outer edge that toggles it on
 * click, the "grab the edge" affordance alongside the explicit `SidebarTrigger` button.
 * Render it as a CHILD of `Sidebar` (it positions itself absolutely against the rail's own
 * `relative` box, and reads which edge to hug from the ancestor's `group-data-[side]/sidebar`
 * — no separate `side` prop to keep in sync). A real `<button>` (not a non-focusable div):
 * keyboard users can Tab to it and toggle with <kbd>Enter</kbd>/<kbd>Space</kbd>, and it picks
 * up the centralized `:focus-visible` outline like every other control — deliberately more
 * accessible than a mouse-only edge-drag handle. Hidden below the mobile breakpoint
 * (`SidebarTrigger` / the Sheet's own affordances cover mobile).
 *
 * @example
 * <Sidebar aria-label="Main navigation">
 *   <SidebarHeader>…</SidebarHeader>
 *   <SidebarContent>…</SidebarContent>
 *   <SidebarRail />
 * </Sidebar>
 */
export function SidebarRail({ className, ...props }: SidebarRailProps) {
  const { toggleSidebar } = useSidebar();
  return (
    <button
      type="button"
      data-slot="sidebar-rail"
      aria-label="Toggle sidebar"
      title="Toggle sidebar"
      onClick={toggleSidebar}
      className={cn(
        "absolute inset-y-0 z-(--z-raised) hidden w-4 -translate-x-1/2 cursor-col-resize items-center justify-center  md:flex",
        "group-data-[side=left]/sidebar:-right-2 group-data-[side=right]/sidebar:-left-2",
        "before:absolute before:inset-y-0 before:left-1/2 before:w-px before:-translate-x-1/2 before:bg-transparent  hover:before:bg-border",
        className,
      )}
      {...props}
    />
  );
}

/** Props accepted by `SidebarInset`. */
export interface SidebarInsetProps extends React.ComponentProps<"main"> {}

/**
 * `SidebarInset` — the main-content wrapper to render as `Sidebar`'s sibling when using
 * `variant="inset"`. Reads the sidebar's `data-variant` through the `peer` relationship (both
 * are children of `SidebarProvider`'s wrapper div): at the `inset` variant, `SidebarInset`
 * itself becomes the rounded/bordered/shadowed panel (with the page background showing
 * through as its margin) — `Sidebar` keeps its normal flush styling. With `variant="sidebar"`
 * / `"floating"`, `SidebarInset` just renders as a plain full-height content column, no panel
 * treatment.
 *
 * @example
 * <SidebarProvider>
 *   <Sidebar variant="inset" aria-label="Main navigation">…</Sidebar>
 *   <SidebarInset>…page content…</SidebarInset>
 * </SidebarProvider>
 */
export function SidebarInset({ className, ...props }: SidebarInsetProps) {
  return (
    <main
      data-slot="sidebar-inset"
      className={cn(
        "relative flex min-h-svh w-full flex-1 flex-col bg-background",
        "md:peer-data-[variant=inset]:m-2 md:peer-data-[variant=inset]:ms-0 md:peer-data-[variant=inset]:rounded-lg md:peer-data-[variant=inset]:border md:peer-data-[variant=inset]:border-border md:peer-data-[variant=inset]:shadow-overlay",
        className,
      )}
      {...props}
    />
  );
}

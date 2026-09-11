import * as React from "react";
import { cn } from "@vegastack/design";
import {
  Sidebar,
  SidebarMenuSkeleton,
  SidebarProvider,
  SidebarTrigger,
  type SidebarProps,
} from "@/components/ui/sidebar";
import { Skeleton } from "@/components/ui/skeleton";

/** Props accepted by `AppShell`. */
export interface AppShellProps extends React.ComponentProps<"div"> {
  /**
   * Initial sidebar open state when uncontrolled — forwarded to `SidebarProvider`.
   * @default true
   */
  defaultOpen?: boolean;
  /**
   * Controlled sidebar open state — forwarded to `SidebarProvider`. Pair with `onOpenChange`.

   * @default undefined
   */
  open?: boolean;
  /** Called whenever the sidebar's open state changes — forwarded to `SidebarProvider`.
   * @default undefined
   */
  onOpenChange?: (open: boolean) => void;
  /**
   * Viewport width (px) below which the sidebar switches into the mobile Sheet — forwarded to
   * `SidebarProvider`.
   * @default 768
   */
  mobileBreakpoint?: number;
  /**
   * Keyboard shortcut that toggles the sidebar — forwarded to `SidebarProvider`. `true` uses
   * Cmd/Ctrl+B, pass a key string to customize, or `false` to disable.
   * @default true
   */
  keyboardShortcut?: boolean | string;
  /**
   * Accessible label for the skip-to-content link — the first focusable element in the shell,
   * always present in the DOM (`sr-only` until focused).
   * @default 'Skip to content'
   */
  skipLinkLabel?: string;
}

/**
 * `AppShell` — the root of the shared dashboard layout. Wraps `SidebarProvider` (forwarding
 * `defaultOpen`/`open`/`onOpenChange`/`mobileBreakpoint`/`keyboardShortcut` — everything the
 * sidebar's expand/collapse and mobile-Sheet behavior needs) and renders the flex row that
 * `AppShellSidebar` and your content column sit in, plus a skip-to-content link
 * (`sr-only focus:not-sr-only`, targeting `AppShellContent`'s `#main-content`) as the very first
 * focusable element in the shell.
 *
 * **No extra wrapper `<div>`.** `SidebarProvider` already renders exactly the flex row a shell
 * needs (`sidebar.tsx`'s internal `sidebar-wrapper` div — `flex min-h-svh w-full`) and forwards
 * `className`/other div props onto it. `AppShell` reuses that same element — overriding its
 * `data-slot` from `"sidebar-wrapper"` to `"app-shell"` — instead of nesting a second flex row
 * around it.
 *
 * **Router-agnostic, by design.** `AppShell` never imports a router and has no opinion on route
 * changes. Moving focus on client-side navigation (to the page's `<h1>`, or to
 * `AppShellContent`'s `<main>` itself) is the DOWNSTREAM app's responsibility — typically a
 * `useEffect` keyed on the router's pathname, in the routed layout/page. See the "Route-change
 * focus" section of this component's docs page for the pattern.
 *
 * **Composition contract.** Render `AppShellSidebar` as one child, then your OWN flex-column
 * `<div>` wrapping `AppShellHeader` + `AppShellContent` as the other. `AppShell` deliberately does
 * NOT render that column for you: it keeps `AppShellHeader`'s `<header>` a true sibling of
 * `AppShellContent`'s `<main>` — never nested inside it, which is what lets `AppShellHeader` keep
 * the `banner` landmark role (a `<header>` descending from `<main>` loses it). See
 * `AppShellContent`'s doc for the rest of that reasoning.
 *
 * @example
 * <AppShell defaultOpen>
 *   <AppShellSidebar>
 *     <SidebarHeader>…logo…</SidebarHeader>
 *     <SidebarContent>…nav…</SidebarContent>
 *   </AppShellSidebar>
 *   <div className="flex h-svh min-w-0 flex-1 flex-col">
 *     <AppShellHeader actions={<Button size="sm">New agent</Button>}>
 *       <Breadcrumb>…</Breadcrumb>
 *     </AppShellHeader>
 *     <AppShellContent>…page content…</AppShellContent>
 *   </div>
 * </AppShell>
 */
export function AppShell({
  defaultOpen,
  open,
  onOpenChange,
  mobileBreakpoint,
  keyboardShortcut,
  skipLinkLabel = "Skip to content",
  className,
  children,
  ...props
}: AppShellProps) {
  return (
    <SidebarProvider
      defaultOpen={defaultOpen}
      open={open}
      onOpenChange={onOpenChange}
      mobileBreakpoint={mobileBreakpoint}
      keyboardShortcut={keyboardShortcut}
      data-slot="app-shell"
      className={className}
      {...props}
    >
      <a
        href="#main-content"
        data-slot="app-shell-skip-link"
        className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:start-2 focus:z-(--z-overlay) focus:rounded-md focus:border focus:border-border focus:bg-background focus:px-3 focus:py-2 focus:text-sm focus:font-medium focus:text-foreground focus:shadow-overlay focus-visible:outline-ring"
      >
        {skipLinkLabel}
      </a>
      {children}
    </SidebarProvider>
  );
}

/** Props accepted by `AppShellSidebar`. */
export interface AppShellSidebarProps extends SidebarProps {}

/**
 * `AppShellSidebar` — a thin, opinionated wrapper over `Sidebar`: defaults `aria-label` to
 * `"Main navigation"` (override it for a differently-named rail) and passes every other prop
 * straight through (`variant`, `collapsible`, `side`, …). Compose your own `SidebarHeader` /
 * `SidebarContent` / `SidebarFooter` as children — exactly as you would with `Sidebar` directly.
 *
 * Renders the same `<nav>` landmark `Sidebar` does, but stamped `data-slot="app-shell-sidebar"`
 * (not `"sidebar"`) so shell-level styling/tests can target it distinctly from a bare `Sidebar`
 * used outside `AppShell`.
 *
 * @example
 * <AppShellSidebar variant="inset">
 *   <SidebarHeader>…</SidebarHeader>
 *   <SidebarContent>…</SidebarContent>
 * </AppShellSidebar>
 */
export function AppShellSidebar({
  "aria-label": ariaLabel = "Main navigation",
  ...props
}: AppShellSidebarProps) {
  return (
    <Sidebar aria-label={ariaLabel} data-slot="app-shell-sidebar" {...props} />
  );
}

/** Props accepted by `AppShellHeader`. */
export interface AppShellHeaderProps extends React.ComponentProps<"header"> {
  /**
   * Right-aligned, `shrink-0` end slot — page-level actions (typically one or more `Button`s or
   * a menu trigger). Omit to hide the slot entirely.

   * @default undefined
   */
  actions?: React.ReactNode;
}

/**
 * `AppShellHeader` — the shell's top row: a real `<header>` (a `banner` landmark — it's always a
 * sibling of `AppShellContent`'s `<main>`, never nested inside it; see the placement note on
 * `AppShell`). Composes `SidebarTrigger` (ALWAYS visible — on mobile it's the only way to open the
 * sidebar, not just a desktop collapse control) + a `min-w-0` middle slot for `children` (a
 * `Breadcrumb`, `BreadcrumbTrail`, or `PageHeader`) + a `shrink-0` `actions` end slot.
 *
 * **Mobile discipline.** The middle slot is `min-w-0 flex-1` so a long breadcrumb trail or title
 * shrinks/truncates instead of pushing `actions` off-screen. Pair it with `BreadcrumbTrail`'s
 * `maxItems` (collapses the middle of a long trail) or `PageHeader`'s `TruncatedText`-backed
 * title — don't let raw, unbounded text wrap the header onto a second line.
 *
 * @example
 * <AppShellHeader actions={<Button size="sm">New agent</Button>}>
 *   <Breadcrumb>
 *     <BreadcrumbList>…</BreadcrumbList>
 *   </Breadcrumb>
 * </AppShellHeader>
 */
export function AppShellHeader({
  className,
  actions,
  children,
  ...props
}: AppShellHeaderProps) {
  return (
    <header
      data-slot="app-shell-header"
      className={cn(
        "flex h-14 shrink-0 items-center gap-2 border-b border-border bg-background px-4",
        className,
      )}
      {...props}
    >
      <SidebarTrigger />
      <div
        data-slot="app-shell-header-middle"
        className="flex min-w-0 flex-1 items-center gap-2"
      >
        {children}
      </div>
      {actions ? (
        <div
          data-slot="app-shell-header-actions"
          className="flex shrink-0 items-center gap-2"
        >
          {actions}
        </div>
      ) : null}
    </header>
  );
}

/** Props accepted by `AppShellContent`. */
export interface AppShellContentProps extends React.ComponentProps<"main"> {
  /**
   * Panel treatment mirroring the sibling `Sidebar`/`AppShellSidebar`'s `variant` — pass the SAME
   * value on both so the shell reads as one consistent layout. Applied directly as a prop here
   * (not shadcn's `SidebarInset` + CSS `peer` selector) — see the component doc for why.
   * @default 'sidebar'
   */
  variant?: "sidebar" | "floating" | "inset";
}

/**
 * `AppShellContent` — the shell's main region: a real `<main id="main-content" tabIndex={-1}>`,
 * the skip-link's target (`AppShell`'s skip link points at `#main-content`; `tabIndex={-1}` makes
 * it programmatically focusable without joining the normal Tab order).
 *
 * **Container queries, not viewport breakpoints.** Carries `@container/app-shell-content`
 * (Tailwind v4 native `@container`) — the sidebar's expand/collapse changes THIS region's actual
 * width independent of the viewport, so a `sm:`/`lg:` grid would misjudge available space right
 * after a collapse/expand toggle. Write `@sm/app-shell-content:grid-cols-2` (etc.) for any
 * stat-card/grid layout inside it, instead of viewport variants.
 *
 * **Scroll strategy: plain `overflow-y-auto`, not `ScrollArea` — a deliberate choice.** `ScrollArea`
 * was evaluated for this region and rejected: its `Viewport` is itself a second
 * `tabIndex={0}` scrollable landmark, nested inside `<main>` — that fights the skip link's own
 * focus target and adds a second scroll container browsers must apply native scroll-restoration/
 * anchoring semantics to. Plain `overflow-y-auto` keeps `<main>` a single simple scrollable
 * element with native browser back/forward scroll-restoration. Reach for `ScrollArea` yourself,
 * INSIDE `AppShellContent`'s children, only for a nested panel that specifically wants the custom
 * auto-hiding scrollbar treatment — not for the page's own scroll.
 *
 * **Bounded height is the consumer's job.** `AppShellContent` is `flex-1 min-h-0`, so it scrolls
 * internally WHEN its ancestor chain gives it a bounded height — the usage examples wrap
 * `AppShellHeader` + `AppShellContent` in a `flex h-svh flex-col` column for exactly this. Without
 * that bound, `overflow-y-auto` is simply inert and the whole page scrolls instead; both are
 * valid layouts, nothing here forces one over the other.
 *
 * **Don't pair with `SidebarInset`.** `SidebarInset` (`sidebar.tsx`) also renders a `<main>` —
 * composing it alongside `AppShellContent` would produce a SECOND main landmark. For the `inset`
 * panel look (rounded/bordered/shadowed) inside `AppShell`, pass `variant="inset"` to
 * `AppShellContent` itself instead — the same classes, applied directly via this prop rather than
 * `SidebarInset`'s `peer-data-[variant=inset]` selector (which requires being a DIRECT sibling of
 * `Sidebar`'s `<nav>`, incompatible with also keeping `AppShellHeader` a true sibling banner).
 * Reach for `SidebarInset` only when composing `Sidebar` standalone, outside `AppShell`.
 *
 * @example
 * <AppShellContent variant="inset">
 *   <div className="grid grid-cols-1 gap-4 p-4 @sm/app-shell-content:grid-cols-2 @lg/app-shell-content:grid-cols-4">
 *     …stat cards…
 *   </div>
 * </AppShellContent>
 */
export function AppShellContent({
  className,
  variant = "sidebar",
  ...props
}: AppShellContentProps) {
  return (
    <main
      id="main-content"
      tabIndex={-1}
      data-slot="app-shell-content"
      data-variant={variant}
      className={cn(
        "@container/app-shell-content relative flex min-h-0 min-w-0 flex-1 flex-col overflow-y-auto bg-background",
        variant === "inset" &&
          "md:m-2 md:ms-0 md:rounded-lg md:border md:border-border md:shadow-overlay",
        className,
      )}
      {...props}
    />
  );
}

/** Props accepted by `AppShellSkeleton`. */
export interface AppShellSkeletonProps extends React.ComponentProps<"div"> {
  /**
   * Number of nav-row placeholders (`SidebarMenuSkeleton`) in the sidebar column.
   * @default 5
   */
  navItemCount?: number;
  /**
   * Number of stat-card placeholders (`Skeleton shape="card"`) in the content region.
   * @default 4
   */
  statCardCount?: number;
}

/**
 * `AppShellSkeleton` — a full-shell loading composition: a sidebar column (logo circle + N
 * `SidebarMenuSkeleton` rows), a header line, and a content region (a stat-card row via
 * `Skeleton shape="card"` + one tall `shape="rect"` placeholder below it). Decorative
 * (`aria-hidden`) and `aria-busy`, matching `Skeleton`'s own convention; deterministic across
 * renders — no `Math.random()`, `SidebarMenuSkeleton`'s own `index`-cycled widths do the varying.
 *
 * **Server-safe**, despite composing `SidebarMenuSkeleton` (defined inside `sidebar.tsx`, a
 * `'use client'` module): `SidebarMenuSkeleton` itself has no hooks and no client-only logic, and
 * — per the React Server Components boundary rules — a Server Component MAY import and render a
 * Client Component as JSX without itself becoming a Client Component (only the DECLARING module
 * crosses the boundary; rendering it as a child from a Server Component is the normal, supported
 * way to mount an interactive island). `AppShellSkeleton` therefore carries no `'use client'` of
 * its own and drops straight into a Next.js `loading.tsx` (a Server Component by default).
 *
 * @example
 * // app/(dashboard)/loading.tsx — a Server Component, no 'use client' needed.
 * export default function Loading() {
 *   return <AppShellSkeleton navItemCount={6} statCardCount={4} />;
 * }
 */
export function AppShellSkeleton({
  className,
  navItemCount = 5,
  statCardCount = 4,
  ...props
}: AppShellSkeletonProps) {
  return (
    <div
      data-slot="app-shell-skeleton"
      role="presentation"
      aria-hidden="true"
      aria-busy="true"
      className={cn("flex min-h-svh w-full", className)}
      {...props}
    >
      {/* hidden md:flex mirrors the real shell: below the mobile breakpoint (SidebarProvider's
          default 768px = Tailwind `md`) the rail collapses into an off-screen Sheet, so the
          skeleton must not paint a sidebar column the loaded shell won't have. */}
      <div className="hidden h-svh w-(--sidebar-width) shrink-0 flex-col gap-2 border-e border-border bg-sidebar p-2 md:flex">
        <div className="flex items-center gap-2 p-2">
          <Skeleton shape="circle" className="size-(--icon-default)" />
          <Skeleton className="h-4 w-24" />
        </div>
        <div className="flex flex-1 flex-col gap-1">
          {Array.from({ length: Math.max(0, navItemCount) }, (_, i) => (
            <SidebarMenuSkeleton key={i} index={i} />
          ))}
        </div>
      </div>

      <div className="flex h-svh min-w-0 flex-1 flex-col">
        <div className="flex h-14 shrink-0 items-center gap-2 border-b border-border px-4">
          <Skeleton shape="circle" className="size-(--icon-default)" />
          <Skeleton className="h-4 w-32" />
        </div>
        <div className="@container/app-shell-content flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto p-4">
          <div className="grid grid-cols-1 gap-4 @sm/app-shell-content:grid-cols-2 @lg/app-shell-content:grid-cols-4">
            {Array.from({ length: Math.max(0, statCardCount) }, (_, i) => (
              <Skeleton key={i} shape="card" className="h-24" />
            ))}
          </div>
          <Skeleton shape="rect" className="h-64 flex-1" />
        </div>
      </div>
    </div>
  );
}

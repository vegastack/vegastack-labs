"use client";

/**
 * `app-sidebar.tsx` — the dashboard-01 block's navigation rail: an AI-platform-flavored nav-main
 * (Dashboard / Agents / Tasks / Usage / Settings) plus a nav-user footer (`Avatar` +
 * `DropdownMenu`). Composes `AppShellSidebar`/`Sidebar`'s public API only — no new primitive.
 *
 * 'use client' — the active-nav-item comparison is presentational-only (no router coupling), but
 * the footer's `DropdownMenu` is interactive, so the whole file crosses the client boundary.
 * `DashboardPage` (`../page.tsx`) stays server-safe by importing this as a client leaf, exactly
 * like `AppShellSkeleton`'s doc describes for `SidebarMenuSkeleton`.
 *
 * Zero Next.js imports (house rule): nav links render as plain `<a>` via `SidebarMenuButton`'s
 * `render` prop — swap in your router's `Link` at the call site (`render={<Link href={...} />}`)
 * without touching this file's structure.
 */

import {
  BarChart3,
  Bot,
  ChevronsUpDown,
  CreditCard,
  LayoutDashboard,
  ListChecks,
  LogOut,
  Settings,
  User,
  type LucideIcon,
} from "lucide-react";
import { AppShellSidebar } from "@/components/ui/app-shell";
import { Avatar } from "@/components/ui/avatar";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar";

interface NavItem {
  key: "dashboard" | "agents" | "tasks" | "usage" | "settings";
  label: string;
  href: string;
  icon: LucideIcon;
}

const NAV_ITEMS: readonly NavItem[] = [
  {
    key: "dashboard",
    label: "Dashboard",
    href: "/dashboard",
    icon: LayoutDashboard,
  },
  { key: "agents", label: "Agents", href: "/dashboard/agents", icon: Bot },
  { key: "tasks", label: "Tasks", href: "/dashboard/tasks", icon: ListChecks },
  { key: "usage", label: "Usage", href: "/dashboard/usage", icon: BarChart3 },
  {
    key: "settings",
    label: "Settings",
    href: "/dashboard/settings",
    icon: Settings,
  },
];

export interface AppSidebarUser {
  name: string;
  email: string;
  /** Resolved, public avatar URL — see `Avatar`'s doc; this component does not resolve storage keys. @default undefined */
  avatarUrl?: string;
}

/** Props accepted by `AppSidebar`. */
export interface AppSidebarProps {
  /** Which nav item is current — highlights it and sets `aria-current="page"`. @default 'dashboard' */
  activeKey?: NavItem["key"];
  /** The signed-in user shown in the footer menu. @default bundled sample user */
  user?: AppSidebarUser;
  /** Called when "Log out" is selected — presentational only, no session logic here. @default undefined */
  onLogout?: () => void;
}

const DEFAULT_USER: AppSidebarUser = {
  name: "Ada Lovelace",
  email: "ada@vegastack.com",
};

function initialsOf(name: string): string {
  return name
    .split(" ")
    .filter(Boolean)
    .map((part) => part[0])
    .slice(0, 2)
    .join("")
    .toUpperCase();
}

/**
 * `AppSidebar` — `AppShellSidebar` composed with the block's nav-main + nav-user footer. The
 * `[view-transition-name:dashboard-shell-sidebar]` arbitrary property (Tailwind v4 native
 * arbitrary-property syntax — a CSS custom-ident, not a hex/px literal, so it stays clean under
 * design-lint's arbitrary-value contract) marks the rail as a STABLE region for the block's View
 * Transitions wiring — see the block's docs page "View Transitions" section for the full
 * mechanism and the required `next.config.js` flag.
 *
 * @example <AppSidebar activeKey="usage" user={{ name: 'Ada', email: 'ada@example.com' }} />
 */
export function AppSidebar({
  activeKey = "dashboard",
  user = DEFAULT_USER,
  onLogout,
}: AppSidebarProps) {
  const initials = initialsOf(user.name);

  return (
    <AppShellSidebar className="[view-transition-name:dashboard-shell-sidebar]">
      <SidebarHeader>
        <div className="flex items-center gap-2 px-2 py-1.5">
          <div
            aria-hidden
            className="flex size-(--icon-feature) shrink-0 items-center justify-center rounded-md bg-primary text-primary-foreground"
          >
            <Bot className="size-(--icon-default)" />
          </div>
          <span className="truncate text-label font-medium text-foreground group-data-[state=collapsed]/sidebar:hidden">
            VegaStack AI
          </span>
        </div>
      </SidebarHeader>

      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupLabel>Platform</SidebarGroupLabel>
          <SidebarMenu>
            {NAV_ITEMS.map((item) => (
              <SidebarMenuItem key={item.key}>
                <SidebarMenuButton
                  isActive={activeKey === item.key}
                  render={<a href={item.href} />}
                >
                  <item.icon />
                  <span>{item.label}</span>
                </SidebarMenuButton>
              </SidebarMenuItem>
            ))}
          </SidebarMenu>
        </SidebarGroup>
      </SidebarContent>

      <SidebarFooter>
        <DropdownMenu>
          <DropdownMenuTrigger className="flex w-full items-center gap-2 rounded-md p-2 text-left hover:bg-sidebar-accent hover:text-sidebar-accent-foreground">
            <Avatar
              size="sm"
              src={user.avatarUrl}
              alt={user.avatarUrl ? user.name : ""}
              fallback={initials}
            />
            {/* min-w-0 on the label column — the sidebar footer row's trailing chevron is a fixed
                sibling, so the name/email column needs min-w-0 to truncate instead of overflowing
                (the same flex-discipline footgun the app-shell audit flags for stat cards/cards). */}
            <span className="flex min-w-0 flex-1 flex-col group-data-[state=collapsed]/sidebar:hidden">
              <span className="truncate text-sm font-medium text-sidebar-foreground">
                {user.name}
              </span>
              <span className="truncate text-sm text-muted-foreground">
                {user.email}
              </span>
            </span>
            <ChevronsUpDown
              aria-hidden
              className="size-(--icon-inline) shrink-0 text-muted-foreground group-data-[state=collapsed]/sidebar:hidden"
            />
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start" side="top" className="w-56">
            <DropdownMenuLabel>{user.name}</DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem>
              <User />
              Profile
            </DropdownMenuItem>
            <DropdownMenuItem>
              <CreditCard />
              Billing
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem variant="destructive" onClick={onLogout}>
              <LogOut />
              Log out
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </SidebarFooter>
    </AppShellSidebar>
  );
}

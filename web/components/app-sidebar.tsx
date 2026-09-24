"use client";

import { Boxes, ClipboardCheck, DatabaseBackup, FileClock, LayoutDashboard, Plug, Server, Settings, ShieldCheck, Users, type LucideIcon } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { AppShellSidebar } from "@/components/ui/app-shell";
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
  label: string;
  href: string;
  icon: LucideIcon;
}

const controlNav: readonly NavItem[] = [
  { label: "Overview", href: "/", icon: LayoutDashboard },
  { label: "Nodes", href: "/nodes", icon: Boxes },
  { label: "People", href: "/people", icon: Users },
  { label: "Services", href: "/services", icon: Server },
  { label: "Backups", href: "/backups", icon: DatabaseBackup },
  { label: "Providers", href: "/providers", icon: Plug },
  { label: "Gates", href: "/gates", icon: ShieldCheck },
  { label: "Audit", href: "/audit", icon: FileClock },
  { label: "Changes", href: "/changes", icon: ClipboardCheck },
];

// Not yet implemented — the links resolve to the honest "unavailable" screen.
const plannedNav: readonly NavItem[] = [
  { label: "Settings", href: "/unavailable", icon: Settings },
];

function NavList({ items, pathname }: { items: readonly NavItem[]; pathname: string }) {
  return (
    <SidebarMenu>
      {items.map((item) => {
        const active = item.href !== "/unavailable" && pathname === item.href;
        return (
          <SidebarMenuItem key={item.label}>
            <SidebarMenuButton
              isActive={active}
              render={<Link href={item.href} prefetch={false} aria-current={active ? "page" : undefined} />}
            >
              <item.icon aria-hidden />
              <span>{item.label}</span>
            </SidebarMenuButton>
          </SidebarMenuItem>
        );
      })}
    </SidebarMenu>
  );
}

export function AppSidebar() {
  const pathname = usePathname();
  return (
    <AppShellSidebar aria-label="Console navigation">
      <SidebarHeader>
        <Link href="/" prefetch={false} className="flex items-center gap-2 px-2 py-1.5 font-medium text-sidebar-foreground">
          <span aria-hidden className="flex size-8 items-center justify-center rounded-md bg-primary text-primary-foreground">
            V
          </span>
          <span className="group-data-[state=collapsed]/sidebar:hidden">VegaStack Labs</span>
        </Link>
      </SidebarHeader>
      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupLabel>Console</SidebarGroupLabel>
          <NavList items={controlNav} pathname={pathname} />
        </SidebarGroup>
        <SidebarGroup>
          <SidebarGroupLabel>Coming soon</SidebarGroupLabel>
          <NavList items={plannedNav} pathname={pathname} />
        </SidebarGroup>
      </SidebarContent>
      <SidebarFooter>
        <p className="px-2 py-1 text-label-sm text-muted-foreground group-data-[state=collapsed]/sidebar:hidden">
          Server-authorized control-plane connection
        </p>
      </SidebarFooter>
    </AppShellSidebar>
  );
}

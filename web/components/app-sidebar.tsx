"use client";

import { Boxes, ClipboardCheck, DatabaseBackup, FileClock, LayoutDashboard, Plug, Server, ShieldCheck, Users, type LucideIcon } from "lucide-react";
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
  { label: "Connections", href: "/providers", icon: Plug },
  { label: "Checks", href: "/gates", icon: ShieldCheck },
  { label: "History checks", href: "/audit", icon: FileClock },
  { label: "Changes", href: "/changes", icon: ClipboardCheck },
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
      </SidebarContent>
      <SidebarFooter>
        <p className="px-2 py-1 text-label-sm text-muted-foreground group-data-[state=collapsed]/sidebar:hidden">
          Connected through the Labs server
        </p>
      </SidebarFooter>
    </AppShellSidebar>
  );
}

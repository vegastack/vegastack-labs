"use client";

import { Boxes, ClipboardCheck, DatabaseBackup, FileClock, LayoutDashboard, Plug, Server, Settings, ShieldCheck, Users, type LucideIcon } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { AppShellSidebar } from "@/components/ui/app-shell";
import { SidebarContent, SidebarFooter, SidebarGroup, SidebarGroupLabel, SidebarHeader, SidebarMenu, SidebarMenuButton, SidebarMenuItem } from "@/components/ui/sidebar";

interface NavItem { label: string; href: string; icon: LucideIcon }
const navItems: readonly NavItem[] = [
  { label: "Overview", href: "/", icon: LayoutDashboard },
  { label: "Nodes", href: "/nodes", icon: Boxes },
  { label: "People", href: "/people", icon: Users },
  { label: "Services", href: "/services", icon: Server },
  { label: "Backups", href: "/backups", icon: DatabaseBackup },
  { label: "Providers", href: "/providers", icon: Plug },
  { label: "Gates", href: "/gates", icon: ShieldCheck },
  { label: "Plans", href: "/unavailable", icon: ClipboardCheck },
  { label: "Audit", href: "/unavailable", icon: FileClock },
  { label: "Settings", href: "/unavailable", icon: Settings },
];

export function AppSidebar() {
  const pathname = usePathname();
  return (
    <AppShellSidebar aria-label="Console navigation">
      <SidebarHeader>
        <Link href="/" prefetch={false} className="flex items-center gap-2 px-2 py-1.5 font-medium text-sidebar-foreground">
          <span aria-hidden className="flex size-8 items-center justify-center rounded-md bg-primary text-primary-foreground">V</span>
          <span className="group-data-[state=collapsed]/sidebar:hidden">VegaStack Labs</span>
        </Link>
      </SidebarHeader>
      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupLabel>Console</SidebarGroupLabel>
          <SidebarMenu>
            {navItems.map((item) => (
              <SidebarMenuItem key={item.label}>
                <SidebarMenuButton className="min-h-11" isActive={item.href !== "/unavailable" && pathname === item.href} render={<Link href={item.href} prefetch={false} />}>
                  <item.icon aria-hidden /><span>{item.label}</span>
                </SidebarMenuButton>
              </SidebarMenuItem>
            ))}
          </SidebarMenu>
        </SidebarGroup>
      </SidebarContent>
      <SidebarFooter><p className="px-2 py-1 text-xs text-muted-foreground group-data-[state=collapsed]/sidebar:hidden">Read-only control-plane connection</p></SidebarFooter>
    </AppShellSidebar>
  );
}

"use client";

import { Boxes, ClipboardCheck, FileClock, LayoutDashboard, Settings, type LucideIcon } from "lucide-react";
import Link from "next/link";
import { AppShellSidebar } from "@/components/ui/app-shell";
import { SidebarContent, SidebarFooter, SidebarGroup, SidebarGroupLabel, SidebarHeader, SidebarMenu, SidebarMenuButton, SidebarMenuItem } from "@/components/ui/sidebar";

interface NavItem { label: string; href: string; icon: LucideIcon }
const navItems: readonly NavItem[] = [
  { label: "Overview", href: "/", icon: LayoutDashboard },
  { label: "Inventory", href: "/unavailable", icon: Boxes },
  { label: "Plans", href: "/unavailable", icon: ClipboardCheck },
  { label: "Audit", href: "/unavailable", icon: FileClock },
  { label: "Settings", href: "/unavailable", icon: Settings },
];

export function AppSidebar() {
  return (
    <AppShellSidebar aria-label="Console navigation">
      <SidebarHeader>
        <Link href="/" className="flex items-center gap-2 px-2 py-1.5 font-medium text-sidebar-foreground">
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
                <SidebarMenuButton render={<Link href={item.href} />}>
                  <item.icon aria-hidden /><span>{item.label}</span>
                </SidebarMenuButton>
              </SidebarMenuItem>
            ))}
          </SidebarMenu>
        </SidebarGroup>
      </SidebarContent>
      <SidebarFooter><p className="px-2 py-1 text-xs text-muted-foreground group-data-[state=collapsed]/sidebar:hidden">Static preview · no live connection</p></SidebarFooter>
    </AppShellSidebar>
  );
}

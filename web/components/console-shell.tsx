import type { ReactNode } from "react";
import { AppShell, AppShellContent, AppShellHeader } from "@/components/ui/app-shell";
import { Breadcrumb, BreadcrumbTrail } from "@/components/ui/breadcrumb";
import { AppSidebar } from "@/components/app-sidebar";
import { ThemeToggle } from "@/components/theme-toggle";

/**
 * The Console chrome: sidebar + a slim top bar carrying the breadcrumb and theme
 * toggle, over a centred scroll region. Each view renders its own `PageHeader`
 * (title, description, refresh) as the first child, so the page owns its header
 * and actions.
 */
export function ConsoleShell({ children, title }: { children: ReactNode; title: string }) {
  return (
    <AppShell defaultOpen skipLinkLabel="Skip to main content">
      <AppSidebar />
      <div className="flex h-svh min-w-0 flex-1 flex-col">
        <AppShellHeader actions={<ThemeToggle />}>
          <Breadcrumb>
            <BreadcrumbTrail items={[{ label: "VegaStack Labs", href: "/" }, { label: title }]} />
          </Breadcrumb>
        </AppShellHeader>
        <AppShellContent aria-label={title} tabIndex={0}>
          <div className="mx-auto flex w-full max-w-6xl flex-col gap-8 p-4 sm:p-6 lg:p-8">
            {children}
          </div>
        </AppShellContent>
      </div>
    </AppShell>
  );
}

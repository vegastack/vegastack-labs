import type { ReactNode } from "react";
import { AppShell, AppShellContent, AppShellHeader } from "@/components/ui/app-shell";
import { Breadcrumb, BreadcrumbTrail } from "@/components/ui/breadcrumb";
import { AppSidebar } from "@/app/dashboard/components/app-sidebar";
import { ThemeToggle } from "@/components/theme-toggle";

export function ConsoleShell({ children, title }: { children: ReactNode; title: string }) {
  return (
    <AppShell defaultOpen skipLinkLabel="Skip to main content">
      <AppSidebar />
      <div className="flex h-svh min-w-0 flex-1 flex-col">
        <AppShellHeader actions={<ThemeToggle />}>
          <Breadcrumb><BreadcrumbTrail items={[{ label: "VegaStack Labs", href: "/" }, { label: title }]} /></Breadcrumb>
        </AppShellHeader>
        <AppShellContent aria-label={title}>
          <div className="mx-auto flex min-h-full w-full max-w-5xl flex-col gap-6 p-4 sm:p-8">
            <header className="space-y-2">
              <p className="text-label-sm uppercase tracking-wide text-muted-foreground">Console preview</p>
              <h1 className="text-2xl font-semibold tracking-tight text-foreground">{title}</h1>
            </header>
            {children}
          </div>
        </AppShellContent>
      </div>
    </AppShell>
  );
}

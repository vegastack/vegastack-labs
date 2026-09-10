import { AlertTriangle, PlusCircle } from "lucide-react";
import {
  AppShell,
  AppShellContent,
  AppShellHeader,
} from "@/components/ui/app-shell";
import { Breadcrumb, BreadcrumbTrail } from "@/components/ui/breadcrumb";
import { Button } from "@/components/ui/button";
import {
  Empty,
  EmptyContent,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty";
import { AppSidebar } from "./components/app-sidebar";
import { DashboardChart, type UsagePoint } from "./components/dashboard-chart";
import { RecentActivity, type ActivityRow } from "./components/recent-activity";
import { StatCards, type StatCardDatum } from "./components/stat-cards";
import sampleData from "./data.json";

const DEFAULT_DATA = sampleData as {
  stats: StatCardDatum[];
  usage: UsagePoint[];
  activity: ActivityRow[];
};

/** Props accepted by `DashboardPage`. */
export interface DashboardPageProps {
  /** Class name forwarded to the root `AppShell` (useful when embedding the block in a bounded preview). @default undefined */
  className?: string;
  /** Viewport width below which navigation uses AppShell's modal Sheet. @default 768 */
  mobileBreakpoint?: number;
  /** Stat-card row data. @default bundled sample `data.json` */
  stats?: StatCardDatum[];
  /** "Usage over time" chart series. @default bundled sample `data.json` */
  usage?: UsagePoint[];
  /** Recent-activity rows. @default bundled sample `data.json` */
  activity?: ActivityRow[];
  /** Per-region loading flags — each region shows its own skeleton independently. @default {} */
  loading?: { stats?: boolean; chart?: boolean; activity?: boolean };
  /** Per-region error messages — each region shows an inline error `Empty` instead of its content. @default {} */
  error?: { stats?: string; chart?: string; activity?: string };
  /**
   * True when the workspace genuinely has no agents/tasks yet — renders a full-page `Empty`
   * zero-state instead of the stat/chart/activity regions (audit §e item 5, the block's own
   * responsibility, not `AppShell`'s).
   * @default false
   */
  isEmpty?: boolean;
}

/** One region's inline error state — an `Empty` in place of that region's normal content. */
function RegionError({
  title,
  description,
}: {
  title: string;
  description: string;
}) {
  return (
    <Empty size="sm" bordered>
      <EmptyHeader>
        <EmptyMedia intent="destructive">
          <AlertTriangle />
        </EmptyMedia>
        <EmptyTitle>{title}</EmptyTitle>
        <EmptyDescription>{description}</EmptyDescription>
      </EmptyHeader>
    </Empty>
  );
}

/**
 * A complete, editable dashboard starter composed on the shared `AppShell` landmarks.
 *
 * @example
 * <DashboardPage loading={{ activity: true }} />
 */
export function DashboardPage({
  className,
  mobileBreakpoint,
  stats = DEFAULT_DATA.stats,
  usage = DEFAULT_DATA.usage,
  activity = DEFAULT_DATA.activity,
  loading = {},
  error = {},
  isEmpty = false,
}: DashboardPageProps) {
  return (
    <AppShell
      defaultOpen
      className={className}
      mobileBreakpoint={mobileBreakpoint}
    >
      <AppSidebar activeKey="dashboard" />
      <div className="flex h-svh min-w-0 flex-1 flex-col">
        <AppShellHeader
          className="[view-transition-name:dashboard-shell-header]"
          actions={
            <Button size="sm">
              <PlusCircle />
              New agent
            </Button>
          }
        >
          <Breadcrumb>
            <BreadcrumbTrail
              items={[{ label: "Home", href: "/" }, { label: "Dashboard" }]}
            />
          </Breadcrumb>
        </AppShellHeader>

        <AppShellContent>
          {isEmpty ? (
            <div className="flex flex-1 items-center justify-center p-4">
              <Empty size="lg">
                <EmptyHeader>
                  <EmptyMedia intent="info">
                    <PlusCircle />
                  </EmptyMedia>
                  <EmptyTitle>No agents yet</EmptyTitle>
                  <EmptyDescription>
                    Create your first agent to start seeing usage, tasks, and
                    activity here.
                  </EmptyDescription>
                </EmptyHeader>
                <EmptyContent>
                  <Button>
                    <PlusCircle />
                    New agent
                  </Button>
                </EmptyContent>
              </Empty>
            </div>
          ) : (
            <div className="flex flex-col gap-4 p-4">
              {error.stats ? (
                <RegionError
                  title="Couldn't load stats"
                  description={error.stats}
                />
              ) : (
                <StatCards stats={stats} loading={loading.stats} />
              )}

              {error.chart ? (
                <RegionError
                  title="Couldn't load the usage chart"
                  description={error.chart}
                />
              ) : (
                <DashboardChart data={usage} loading={loading.chart} />
              )}

              {error.activity ? (
                <RegionError
                  title="Couldn't load recent activity"
                  description={error.activity}
                />
              ) : (
                <RecentActivity data={activity} loading={loading.activity} />
              )}
            </div>
          )}
        </AppShellContent>
      </div>
    </AppShell>
  );
}

// Next.js app-route target (`app/dashboard/page.tsx`) — route files REQUIRE a default
// export; the named export above stays for composition/tests.
export default DashboardPage;

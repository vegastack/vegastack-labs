"use client";

/**
 * `recent-activity.tsx` — the dashboard-01 block's recent-activity `DataList` (audit §e item 4):
 * task/agent name (`IconText`), status (`StatusIcon`), started (`RelativeTime`), duration
 * (`TableCellText`, `mono`). Wires `DataList`'s own built-in `loading` skeleton rows and a
 * custom `emptyState` ("No activity yet" + a CTA).
 *
 * 'use client' — `DataList`, `IconText`/`TruncatedText`, and `RelativeTime` are all client leaves
 * (ResizeObserver / Tooltip / timers).
 */

import * as React from "react";
import { FileText, ListChecks } from "lucide-react";
import { Button } from "@/components/ui/button";
import { DataList, type DataListColumn } from "@/components/ui/data-list";
import {
  Empty,
  EmptyContent,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty";
import { RelativeTime } from "@/components/ui/relative-time";
import { StatusIcon, type StatusIconProps } from "@/components/ui/status-icon";
import { IconText, TableCellText } from "@/components/ui/truncated-text";

export interface ActivityRow {
  /** Stable row identifier. */
  id: string;
  /** Human-readable task or run name. */
  name: string;
  /** Semantic run status. */
  status: NonNullable<StatusIconProps["status"]>;
  /** ISO instant the task/run started. */
  startedAt: string;
  /** Elapsed duration in milliseconds. */
  durationMs: number;
}

/**
 * Fixed reference instant the "started" column's `RelativeTime` is measured against.
 *
 * **Determinism investigation (house rule: no `Date.now()`/`Math.random()` anywhere a VRT
 * screenshot can see):** `RelativeTime` (`packages/ui/registry/ui/relative-time.tsx`) defaults to
 * the live clock (`Date.now()`) and re-renders on a timer. Its API exposes exactly the escape
 * hatch this block needs — a `now` prop (epoch ms) that replaces the live clock for the "X ago"
 * computation, paired with `refresh={false}` to also suppress the internal `setTimeout` re-render
 * loop (`isControlled = now !== undefined` short-circuits the timer effect in the source). Passing
 * both together is `RelativeTime`'s documented deterministic mode — every render, at any wall-clock
 * time, produces the identical "X ago" string. `DASHBOARD_NOW_MS` matches `data.json`'s
 * `generatedAt` so the demo's relative strings stay sensible (e.g. "6 minutes ago") without ever
 * reading the real clock.
 */
const DASHBOARD_NOW_MS = Date.parse("2026-07-14T09:00:00.000Z");

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  const totalSeconds = Math.round(ms / 1000);
  if (totalSeconds < 60) return `${totalSeconds}s`;
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return `${minutes}m ${seconds}s`;
}

const columns: DataListColumn<ActivityRow>[] = [
  {
    key: "name",
    header: "Task",
    render: (row) => <IconText icon={<FileText />} text={row.name} />,
  },
  {
    key: "status",
    header: "Status",
    render: (row) => (
      <span className="flex items-center gap-1.5">
        <StatusIcon status={row.status} size="sm" />
        <span className="text-base text-foreground">
          {row.status === "progress"
            ? "In progress"
            : row.status === "todo"
              ? "To do"
              : row.status}
        </span>
      </span>
    ),
  },
  {
    key: "startedAt",
    header: "Started",
    render: (row) => (
      <RelativeTime
        date={row.startedAt}
        now={DASHBOARD_NOW_MS}
        refresh={false}
        className="text-muted-foreground"
      />
    ),
  },
  {
    key: "durationMs",
    header: "Duration",
    align: "end",
    render: (row) => (
      <TableCellText text={formatDuration(row.durationMs)} mono />
    ),
  },
];

/** Props accepted by `RecentActivity`. */
export interface RecentActivityProps {
  /** Deterministic activity rows to display. */
  data: ActivityRow[];
  /** Shows `DataList`'s built-in skeleton rows instead of `data` — the region's own loading state. @default false */
  loading?: boolean;
}

/** `RecentActivity` — the recent-activity `DataList`. @example <RecentActivity data={activity} /> */
export function RecentActivity({ data, loading = false }: RecentActivityProps) {
  return (
    <DataList
      data-slot="dashboard-recent-activity"
      columns={columns}
      data={data}
      getRowId={(row) => row.id}
      loading={loading}
      loadingRows={5}
      emptyState={
        <Empty size="sm">
          <EmptyHeader>
            <EmptyMedia>
              <ListChecks />
            </EmptyMedia>
            <EmptyTitle>No activity yet</EmptyTitle>
            <EmptyDescription>
              Tasks and agent runs will show up here once they start.
            </EmptyDescription>
          </EmptyHeader>
          <EmptyContent>
            <Button
              size="sm"
              variant="outline"
              render={<a href="/dashboard/tasks" />}
            >
              View tasks
            </Button>
          </EmptyContent>
        </Empty>
      }
    />
  );
}

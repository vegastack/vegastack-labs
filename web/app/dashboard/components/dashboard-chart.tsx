"use client";

/**
 * `dashboard-chart.tsx` — the dashboard-01 block's "Usage over time" card (audit §e item 3):
 * `ChartContainer` + a Recharts `AreaChart` over static, deterministic data (`requests`/`errors`
 * for the last 7 days), themed with the `chart-1`/`chart-2` tokens. `accessibilityLayer` is set
 * explicitly per `chart.tsx`'s own doc, so the chart is keyboard-navigable, not just a static image.
 *
 * 'use client' — Recharts renders into the DOM (ResizeObserver-driven `ResponsiveContainer`).
 */

import * as React from "react";
import { Area, AreaChart, CartesianGrid, XAxis, YAxis } from "recharts";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart";
import { Skeleton } from "@/components/ui/skeleton";

export interface UsagePoint {
  /** Display label for the x-axis point. */
  date: string;
  /** Request volume at this point. */
  requests: number;
  /** Error volume at this point. */
  errors: number;
}

/** Props accepted by `DashboardChart`. */
export interface DashboardChartProps {
  /** Deterministic usage series displayed by the chart. */
  data: UsagePoint[];
  /** Shows a skeleton placeholder instead of the chart — the region's own loading state. @default false */
  loading?: boolean;
}

const chartConfig = {
  requests: { label: "Requests", color: "chart-1" },
  errors: { label: "Errors", color: "chart-2" },
} satisfies ChartConfig;

/** `DashboardChart` — a `Card` wrapping the themed area chart, or its loading placeholder. @example <DashboardChart data={usage} /> */
export function DashboardChart({ data, loading = false }: DashboardChartProps) {
  return (
    <Card data-slot="dashboard-chart">
      <CardHeader>
        <CardTitle>Usage over time</CardTitle>
        <CardDescription>
          Requests and errors for the last 7 days.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {loading ? (
          <Skeleton shape="rect" className="h-64 w-full" aria-hidden="true" />
        ) : (
          <ChartContainer
            config={chartConfig}
            className="aspect-auto h-64 w-full"
          >
            <AreaChart
              accessibilityLayer
              data={data}
              margin={{ left: 0, right: 0 }}
            >
              <CartesianGrid vertical={false} stroke="var(--border)" />
              <XAxis
                dataKey="date"
                tickLine={false}
                axisLine={false}
                tickMargin={8}
              />
              <YAxis
                tickLine={false}
                axisLine={false}
                tickMargin={8}
                width={44}
              />
              <ChartTooltip
                cursor={{ stroke: "var(--border)" }}
                content={<ChartTooltipContent />}
              />
              <Area
                dataKey="requests"
                type="monotone"
                fill="var(--color-requests)"
                fillOpacity={0.2}
                stroke="var(--color-requests)"
                strokeWidth={2}
              />
              <Area
                dataKey="errors"
                type="monotone"
                fill="var(--color-errors)"
                fillOpacity={0.2}
                stroke="var(--color-errors)"
                strokeWidth={2}
              />
            </AreaChart>
          </ChartContainer>
        )}
      </CardContent>
    </Card>
  );
}

"use client";

import * as React from "react";
import * as RechartsPrimitive from "recharts";
import type { TooltipValueType } from "recharts";
import { cn } from "@vegastack/design";

/* ------------------------------------------------------------------------------------------------
 * Chart — a themed wrapper around Recharts 3. Exports `ChartContainer` (sizing + the `ChartConfig`
 * context), `ChartTooltip`/`ChartTooltipContent`, `ChartLegend`/`ChartLegendContent`, and the
 * `ChartConfig` type. Compose it with Recharts' own primitives (`LineChart`, `BarChart`,
 * `CartesianGrid`, `XAxis`, …) imported directly from `recharts` — this file does not re-wrap them.
 *
 * THEMING — token-only, no per-config theme map. shadcn/ui's reference Chart injects a `<style>` tag
 * with a `{ light: '', dark: '.dark' }` `THEMES` selector map and lets `ChartConfig` entries carry a
 * `{ light, dark }` hex/oklch pair (`ChartStyle`). VegaStack's chart palette is already theme-split at
 * the TOKEN layer instead — `--chart-1`…`--chart-8` are defined once in `packages/design-tokens` for both
 * `:root` and `.dark`. So here `ChartConfig.color` accepts ONLY a chart-token reference
 * ({@link ChartColorToken}, e.g. `'chart-1'`, or the literal `'var(--chart-1)'`) — never a hex/oklch
 * literal and never a `{ light, dark }` pair. `ChartContainer` resolves each entry to a
 * `--color-<key>: var(--chart-N)` custom property set directly in the container's `style` — no
 * injected stylesheet, no `React.useId()` + `data-chart` selector-scoping needed, because the var is
 * scoped by ordinary DOM ancestry (children read whatever `--color-<key>` their nearest ancestor
 * declares), not by a global CSS selector matching an id attribute. It also stays theme-reactive for
 * free: `var(--chart-N)` re-resolves against whichever theme scope (`:root` / `.dark`) the container
 * happens to sit under, exactly like every other semantic color token in this system — there is
 * nothing chart-specific left to keep in sync. The `THEMES`/`ChartStyle` mechanism is deleted
 * entirely, on purpose (locked in `docs/plans/`): it would only re-implement work the token layer
 * already does.
 *
 * STYLING RECHARTS PRIMITIVES (grid / cursor / dot) — `ChartContainer` themes only what a generic
 * sizing wrapper safely can for every chart shape: axis-tick label color, plus a few
 * outline/focus-ring resets on Recharts' own SVG layers. Grid-line, hover-cursor, and point-dot
 * stroke/fill colors are Recharts SVG PRESENTATION ATTRIBUTES baked into the library itself
 * (`<CartesianGrid>` defaults to `stroke="#ccc"`, `<Line>` dots default to `stroke="#fff"`, the
 * BarChart hover cursor defaults to `stroke="#ccc"`, …). The shadcn reference overrides these with
 * `[&_.recharts-x[stroke='#ccc']]:stroke-border/50`-style attribute-VALUE selectors that (a) embed
 * hex literals this repo's design-lint bans outright and (b) silently stop matching the instant a
 * future Recharts version changes its internal default — verified against the installed recharts
 * 3.9.2 source (`node_modules/recharts/es6/**`) while building this component. We don't replicate
 * that hack. Instead, set these colors directly as props on the Recharts primitive you compose — the
 * normal, version-stable Recharts API — using our tokens:
 *   `<CartesianGrid stroke="var(--border)" vertical={false} />`
 *   `<Tooltip cursor={{ stroke: 'var(--border)' }} />` (Line/Area) or `{{ fill: 'var(--muted)' }}` (Bar)
 *   `<Line dot={{ fill: 'var(--color-desktop)', r: 4 }} />`
 * Every documented example below does this.
 *
 * ACCESSIBILITY — pass `accessibilityLayer` on the Recharts chart element (`<LineChart
 * accessibilityLayer>`, `<BarChart accessibilityLayer>`, …) in every chart you ship. Verified against
 * the installed recharts 3.9.2 (`node_modules/recharts/es6/container/RootSurface.js`): when on, the
 * chart's root `<svg>` gets `role="application"` and `tabIndex={0}`, and Recharts' own
 * `AccessibilityLayer` wires arrow-key navigation between data points plus a live region that
 * announces the active point — a real interaction layer, not a static image. `ChartContainer` does
 * NOT add its own `role="img"` (that would collide with Recharts' `role="application"`); the
 * accessible surface is Recharts' own. As of 3.9.2 `accessibilityLayer` already DEFAULTS to `true` on
 * every Cartesian/Polar chart — we still set it explicitly in every example so it (a) reads as
 * intentional, not incidental, and (b) survives a future Recharts version changing that default.
 * ----------------------------------------------------------------------------------------------*/

/** One of the theme-split chart series tokens (`packages/design-tokens`, `:root` + `.dark`). */
export type ChartColorToken =
  | "chart-1"
  | "chart-2"
  | "chart-3"
  | "chart-4"
  | "chart-5"
  | "chart-6"
  | "chart-7"
  | "chart-8";

/**
 * `ChartConfig` — maps a data key (a `dataKey` on a `<Line>`/`<Bar>`/`<Area>`, or an axis field looked
 * up by label) to its label, optional icon, and series color. `color` is TOKEN-ONLY — pass a bare
 * token name (`'chart-1'`) or the literal CSS var reference (`'var(--chart-1)'`); both resolve to the
 * same `--color-<key>` custom property `ChartContainer` sets. There is no hex/oklch literal escape
 * hatch and no `{ light, dark }` theme pair — see the file-level JSDoc for why. Omit `color` on an
 * entry that only supplies a `label`/`icon` for lookup (e.g. an axis field read via
 * {@link ChartTooltipContent}'s `labelKey`, not itself rendered as a colored series).
 *
 * @example
 * const chartConfig = {
 *   desktop: { label: 'Desktop', color: 'chart-1' },
 *   mobile: { label: 'Mobile', color: 'chart-2' },
 * } satisfies ChartConfig;
 */
export type ChartConfig = Record<
  string,
  {
    label?: React.ReactNode;
    icon?: React.ComponentType;
    color?: ChartColorToken | `var(--${ChartColorToken})`;
  }
>;

function resolveChartColor(
  color: ChartColorToken | `var(--${ChartColorToken})`,
): string {
  return color.startsWith("var(") ? color : `var(--${color})`;
}

type ChartContextProps = {
  config: ChartConfig;
};

const ChartContext = React.createContext<ChartContextProps | null>(null);

function useChart(): ChartContextProps {
  const context = React.useContext(ChartContext);

  if (!context) {
    throw new Error("useChart must be used within a <ChartContainer />");
  }

  return context;
}

const DEFAULT_INITIAL_DIMENSION = { width: 320, height: 200 } as const;

/** Props accepted by `ChartContainer`. */
export interface ChartContainerProps extends Omit<
  React.ComponentProps<"div">,
  "children"
> {
  /** Series/label/icon config — see {@link ChartConfig}. Drives each series' `--color-<key>` CSS var
   * and the label/icon lookups in {@link ChartTooltipContent} / {@link ChartLegendContent}. */
  config: ChartConfig;
  /** The Recharts chart element (e.g. `<LineChart>…</LineChart>`) — forwarded as `ResponsiveContainer`'s
   * child (a plain element, not a render-prop — `ResponsiveContainer`'s `children` is `ReactNode` in
   * this recharts version). */
  children: React.ComponentProps<
    typeof RechartsPrimitive.ResponsiveContainer
  >["children"];
  /** Size used for the very first render, before `ResizeObserver` reports the real parent box —
   * avoids a 0×0 flash on mount. @default { width: 320, height: 200 } */
  initialDimension?: { width: number; height: number };
}

/**
 * `ChartContainer` — sizes and themes a Recharts chart. Renders Recharts' `ResponsiveContainer` inside
 * a `<div>` that (1) exposes each {@link ChartConfig} entry's color as a `--color-<key>` CSS custom
 * property for `var(--color-<key>)` fills/strokes on your series, and (2) provides `config` via
 * context to {@link ChartTooltipContent} / {@link ChartLegendContent} for label + icon lookups. See
 * the file-level JSDoc for the token-only theming model and how to color Recharts primitives
 * (grid/cursor/dot) directly. Renders a `<div>`.
 *
 * @example
 * const chartConfig = {
 *   desktop: { label: 'Desktop', color: 'chart-1' },
 * } satisfies ChartConfig;
 *
 * <ChartContainer config={chartConfig} className="h-64 w-full">
 *   <RechartsPrimitive.LineChart accessibilityLayer data={data}>
 *     <RechartsPrimitive.CartesianGrid vertical={false} stroke="var(--border)" />
 *     <RechartsPrimitive.XAxis dataKey="month" tickLine={false} axisLine={false} />
 *     <ChartTooltip content={<ChartTooltipContent />} />
 *     <RechartsPrimitive.Line
 *       dataKey="desktop"
 *       stroke="var(--color-desktop)"
 *       strokeWidth={2}
 *       dot={false}
 *     />
 *   </RechartsPrimitive.LineChart>
 * </ChartContainer>
 */
function ChartContainer({
  className,
  children,
  config,
  initialDimension = DEFAULT_INITIAL_DIMENSION,
  style,
  ...props
}: ChartContainerProps) {
  // Each configured series becomes a `--color-<key>` custom property on the container. Scoped by
  // plain DOM ancestry (no id-selector stylesheet needed) and theme-reactive for free — see the
  // file-level THEMING note.
  const chartStyle = React.useMemo(() => {
    const vars: Record<string, string> = {};
    for (const [key, itemConfig] of Object.entries(config)) {
      if (itemConfig.color) {
        vars[`--color-${key}`] = resolveChartColor(itemConfig.color);
      }
    }
    return vars;
  }, [config]);

  return (
    <ChartContext.Provider value={{ config }}>
      <div
        data-slot="chart"
        style={{ ...chartStyle, ...style } as React.CSSProperties}
        className={cn(
          "flex aspect-video justify-center text-xs",
          // Numerals canon: axis tick numerals are mono (SVG <text> takes font-family
          // via class), matching the tooltip's `font-mono tabular-nums` values.
          "[&_.recharts-cartesian-axis-tick_text]:fill-muted-foreground [&_.recharts-cartesian-axis-tick_text]:font-mono",
          "[&_.recharts-layer]:outline-hidden [&_.recharts-sector]:outline-hidden [&_.recharts-surface]:outline-hidden",
          className,
        )}
        {...props}
      >
        <RechartsPrimitive.ResponsiveContainer
          initialDimension={initialDimension}
        >
          {children}
        </RechartsPrimitive.ResponsiveContainer>
      </div>
    </ChartContext.Provider>
  );
}

/**
 * `ChartTooltip` — Recharts' `Tooltip`, re-exported so consumers don't need a second import from
 * `recharts`. Pair with {@link ChartTooltipContent}: `<ChartTooltip content={<ChartTooltipContent />} />`.
 */
const ChartTooltip = RechartsPrimitive.Tooltip;

type TooltipNameType = number | string;

// A `type` intersection, NOT `interface extends` — `React.ComponentProps<typeof Tooltip>` and
// `React.ComponentProps<'div'>` both declare `formatter`/`content`-shaped members with incompatible
// signatures, which `interface extends` rejects (TS2320) but a plain `&` intersection resolves fine.
/** Props accepted by `ChartTooltipContent`. */
export type ChartTooltipContentProps = React.ComponentProps<
  typeof RechartsPrimitive.Tooltip
> &
  React.ComponentProps<"div"> &
  Omit<
    RechartsPrimitive.DefaultTooltipContentProps<
      TooltipValueType,
      TooltipNameType
    >,
    "accessibilityLayer"
  > & {
    /** Hide the label row above the item rows. @default false */
    hideLabel?: boolean;
    /** Hide the per-item color indicator swatch. @default false */
    hideIndicator?: boolean;
    /** Shape of the per-item color swatch. @default 'dot' */
    indicator?: "line" | "dot" | "dashed";
    /** Data key to read the series name from, when it differs from the payload's own `name`/`dataKey`. */
    nameKey?: string;
    /** Data key to read the label from, when it differs from the payload's own `label`. */
    labelKey?: string;
  };

/**
 * `ChartTooltipContent` — the default `content` for {@link ChartTooltip}. Looks up each hovered
 * series' label/icon/color from the {@link ChartContainer}'s `config` via context, and renders a
 * bordered `bg-popover` card with a label row and one row per series (color swatch, label, and a
 * `font-mono` numeric value). Renders a `<div>` (or `null` while inactive).
 *
 * @example
 * <ChartTooltip content={<ChartTooltipContent indicator="line" />} />
 */
function ChartTooltipContent({
  active,
  payload,
  className,
  indicator = "dot",
  hideLabel = false,
  hideIndicator = false,
  label,
  labelFormatter,
  labelClassName,
  formatter,
  color,
  nameKey,
  labelKey,
}: ChartTooltipContentProps) {
  const { config } = useChart();

  const tooltipLabel = React.useMemo(() => {
    if (hideLabel || !payload?.length) {
      return null;
    }

    const [item] = payload;
    const key = `${labelKey ?? item?.dataKey ?? item?.name ?? "value"}`;
    const itemConfig = getPayloadConfigFromPayload(config, item, key);
    const value =
      !labelKey && typeof label === "string"
        ? (config[label]?.label ?? label)
        : itemConfig?.label;

    if (labelFormatter) {
      return (
        <div className={cn("font-medium", labelClassName)}>
          {labelFormatter(value, payload)}
        </div>
      );
    }

    if (!value) {
      return null;
    }

    return <div className={cn("font-medium", labelClassName)}>{value}</div>;
  }, [
    label,
    labelFormatter,
    payload,
    hideLabel,
    labelClassName,
    config,
    labelKey,
  ]);

  if (!active || !payload?.length) {
    return null;
  }

  const nestLabel = payload.length === 1 && indicator !== "dot";

  return (
    <div
      data-slot="chart-tooltip-content"
      className={cn(
        "grid min-w-32 items-start gap-1.5 rounded-lg border border-border bg-popover px-2.5 py-1.5 text-xs text-popover-foreground shadow-overlay",
        className,
      )}
    >
      {!nestLabel ? tooltipLabel : null}
      <div className="grid gap-1.5">
        {payload
          .filter((item) => item.type !== "none")
          .map((item, index) => {
            const key = `${nameKey ?? item.name ?? item.dataKey ?? "value"}`;
            const itemConfig = getPayloadConfigFromPayload(config, item, key);
            const indicatorColor = color ?? item.payload?.fill ?? item.color;

            return (
              <div
                key={index}
                className={cn(
                  "flex w-full flex-wrap items-stretch gap-2 [&>svg]:size-(--icon-compact) [&>svg]:text-muted-foreground",
                  indicator === "dot" && "items-center",
                )}
              >
                {formatter && item?.value !== undefined && item.name ? (
                  formatter(item.value, item.name, item, index, item.payload)
                ) : (
                  <>
                    {itemConfig?.icon ? (
                      <itemConfig.icon />
                    ) : (
                      !hideIndicator && (
                        <div
                          data-slot="chart-tooltip-indicator"
                          className={cn(
                            "shrink-0 rounded-xs border-(--color-border) bg-(--color-bg)",
                            {
                              "size-2.5": indicator === "dot",
                              "w-1": indicator === "line",
                              "w-0 border-2 border-dashed bg-transparent":
                                indicator === "dashed",
                              "my-0.5": nestLabel && indicator === "dashed",
                            },
                          )}
                          style={
                            {
                              "--color-bg": indicatorColor,
                              "--color-border": indicatorColor,
                            } as React.CSSProperties
                          }
                        />
                      )
                    )}
                    <div
                      className={cn(
                        "flex flex-1 justify-between leading-none",
                        nestLabel ? "items-end" : "items-center",
                      )}
                    >
                      <div className="grid gap-1.5">
                        {nestLabel ? tooltipLabel : null}
                        <span className="text-muted-foreground">
                          {itemConfig?.label ?? item.name}
                        </span>
                      </div>
                      {item.value != null && (
                        <span className="font-mono font-medium text-foreground tabular-nums">
                          {typeof item.value === "number"
                            ? item.value.toLocaleString()
                            : String(item.value)}
                        </span>
                      )}
                    </div>
                  </>
                )}
              </div>
            );
          })}
      </div>
    </div>
  );
}

/**
 * `ChartLegend` — Recharts' `Legend`, re-exported so consumers don't need a second import from
 * `recharts`. Pair with {@link ChartLegendContent}: `<ChartLegend content={<ChartLegendContent />} />`.
 */
const ChartLegend = RechartsPrimitive.Legend;

// A `type` intersection for the same reason as ChartTooltipContentProps above: `React.ComponentProps<'div'>`
// and `DefaultLegendContentProps` both declare incompatible members (e.g. `onClick`) that `interface
// extends` rejects.
/** Props accepted by `ChartLegendContent`. */
export type ChartLegendContentProps = React.ComponentProps<"div"> &
  RechartsPrimitive.DefaultLegendContentProps & {
    /** Hide each series' `config.icon` (when present) and always use the color swatch. @default false */
    hideIcon?: boolean;
    /** Data key to read the series name from, when it differs from the payload's own `dataKey`. */
    nameKey?: string;
  };

/**
 * `ChartLegendContent` — the default `content` for {@link ChartLegend}. Looks up each series' label
 * (and optional `config.icon`) from the {@link ChartContainer}'s `config` via context, and renders a
 * centered row of swatch/icon + label pairs. Renders a `<div>` (or `null` with no payload).
 *
 * @example
 * <ChartLegend content={<ChartLegendContent />} />
 */
function ChartLegendContent({
  className,
  hideIcon = false,
  payload,
  verticalAlign = "bottom",
  nameKey,
}: ChartLegendContentProps) {
  const { config } = useChart();

  if (!payload?.length) {
    return null;
  }

  return (
    <div
      data-slot="chart-legend-content"
      className={cn(
        "flex items-center justify-center gap-4",
        verticalAlign === "top" ? "pb-3" : "pt-3",
        className,
      )}
    >
      {payload
        .filter((item) => item.type !== "none")
        .map((item, index) => {
          const key = `${nameKey ?? item.dataKey ?? "value"}`;
          const itemConfig = getPayloadConfigFromPayload(config, item, key);

          return (
            <div
              key={index}
              className="flex items-center gap-1.5 [&>svg]:size-(--icon-compact) [&>svg]:text-muted-foreground"
            >
              {itemConfig?.icon && !hideIcon ? (
                <itemConfig.icon />
              ) : (
                <div
                  data-slot="chart-legend-indicator"
                  className="size-2 shrink-0 rounded-xs bg-(--color-bg)"
                  style={{ "--color-bg": item.color } as React.CSSProperties}
                />
              )}
              {itemConfig?.label}
            </div>
          );
        })}
    </div>
  );
}

// Reads the item config for a tooltip/legend payload entry: prefers a string value found ON the
// payload (or its nested `payload`) at `key` as the config lookup key (lets a `nameKey`/`labelKey`
// resolve through a data field), falling back to `key` itself.
function getPayloadConfigFromPayload(
  config: ChartConfig,
  payload: unknown,
  key: string,
) {
  if (typeof payload !== "object" || payload === null) {
    return undefined;
  }

  const payloadPayload =
    "payload" in payload &&
    typeof payload.payload === "object" &&
    payload.payload !== null
      ? payload.payload
      : undefined;

  let configLabelKey: string = key;

  if (
    key in payload &&
    typeof payload[key as keyof typeof payload] === "string"
  ) {
    configLabelKey = payload[key as keyof typeof payload] as string;
  } else if (
    payloadPayload &&
    key in payloadPayload &&
    typeof payloadPayload[key as keyof typeof payloadPayload] === "string"
  ) {
    configLabelKey = payloadPayload[
      key as keyof typeof payloadPayload
    ] as string;
  }

  return configLabelKey in config ? config[configLabelKey] : config[key];
}

/** Props accepted by `ChartGrid`. */
export type ChartGridProps = React.ComponentProps<
  typeof RechartsPrimitive.CartesianGrid
>;

/**
 * `ChartGrid` — `CartesianGrid` pre-configured to the system's dashboard voice
 * (Wave 2): horizontal-only, DASHED hairlines on the `border` token. Recharts
 * would otherwise default to solid `#ccc` in both themes. Every prop remains
 * overridable (`vertical`, `strokeDasharray`, …).
 *
 * @example
 * <ChartContainer config={config}>
 *   <RechartsPrimitive.BarChart data={data}>
 *     <ChartGrid />
 *     …
 *   </RechartsPrimitive.BarChart>
 * </ChartContainer>
 */
function ChartGrid(props: ChartGridProps) {
  return (
    <RechartsPrimitive.CartesianGrid
      vertical={false}
      stroke="var(--border)"
      strokeDasharray="3 3"
      {...props}
    />
  );
}

export {
  ChartContainer,
  ChartGrid,
  ChartTooltip,
  ChartTooltipContent,
  ChartLegend,
  ChartLegendContent,
};

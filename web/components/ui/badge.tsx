"use client";

import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { useRender } from "@base-ui/react/use-render";
import { Spinner } from "@/components/ui/spinner";
import { cn } from "@vegastack/design";

/**
 * Badge variants — `variant` (subtle / solid / minimal / outline) × `intent` (semantic
 * family) × `size`. Per the v2 spec, badges are `rounded-full` pills: the
 * default `subtle` treatment uses a soft `{family}-subtle` tint + `{family}-text`,
 * `solid` uses the family fill + on-color foreground, and the neutral badge
 * resolves to `muted`. Every value is a semantic Tailwind token (no hardcoded
 * colors, no `color-mix`, no inline styles); tinting per family is expressed via
 * compound variants.
 */
export const badgeVariants = cva(
  // text-ellipsis makes a consumer-supplied max-w-* cap elide instead of hard-clipping —
  // costless at the default w-fit (content never overflows itself).
  "inline-flex w-fit shrink-0 items-center justify-center gap-1 overflow-hidden rounded-full border border-transparent text-ellipsis whitespace-nowrap  [&_svg]:pointer-events-none [&_svg]:shrink-0",
  {
    variants: {
      variant: {
        subtle: "border-transparent",
        solid: "border-transparent",
        minimal: "border-transparent bg-transparent",
        /** Neutral/hued tag chip: hairline border, no fill (Wave 2 — Attio tag formula). */
        outline: "bg-transparent",
      },
      intent: {
        default: "",
        success: "",
        warning: "",
        destructive: "",
        info: "",
      },
      /**
       * Matching-hue border on the `subtle` tint (Wave 2 — the Attio chip
       * formula: tint fill + same-hue border + family text). No-op on other
       * variants; `outline` already carries its border.
       */
      bordered: {
        true: "",
        false: "",
      },
      size: {
        sm: "h-5 gap-1 px-1.5 py-0.5 text-label-sm [&_svg:not([class*='size-'])]:size-(--icon-compact)",
        default:
          "h-5 gap-1 px-2 py-0.5 text-label-sm [&_svg:not([class*='size-'])]:size-(--icon-compact)",
        lg: "h-6 gap-1 px-2.5 py-0.5 text-label-sm [&_svg:not([class*='size-'])]:size-(--icon-inline)",
      },
    },
    compoundVariants: [
      // ── subtle: soft {family}-subtle tint + {family}-text (v2 default) ────
      {
        variant: "subtle",
        intent: "default",
        class: "bg-muted text-muted-foreground",
      },
      {
        variant: "subtle",
        intent: "success",
        class: "bg-success-subtle text-success-text",
      },
      {
        variant: "subtle",
        intent: "warning",
        class: "bg-warning-subtle text-warning-text",
      },
      {
        variant: "subtle",
        intent: "destructive",
        class: "bg-destructive-subtle text-destructive-text",
      },
      {
        variant: "subtle",
        intent: "info",
        class: "bg-info-subtle text-info-text",
      },

      // ── solid: family fill + on-color foreground ──────────────────────────
      {
        variant: "solid",
        intent: "default",
        class: "bg-foreground text-background",
      },
      {
        variant: "solid",
        intent: "success",
        class: "bg-success text-success-foreground",
      },
      {
        variant: "solid",
        intent: "warning",
        class: "bg-warning text-warning-foreground",
      },
      {
        variant: "solid",
        intent: "destructive",
        class: "bg-destructive text-destructive-foreground",
      },
      {
        variant: "solid",
        intent: "info",
        class: "bg-info text-info-foreground",
      },

      // ── minimal: borderless, no bg, colored text only ─────────────────────
      { variant: "minimal", intent: "default", class: "text-muted-foreground" },
      { variant: "minimal", intent: "success", class: "text-success-text" },
      { variant: "minimal", intent: "warning", class: "text-warning-text" },
      {
        variant: "minimal",
        intent: "destructive",
        class: "text-destructive-text",
      },
      { variant: "minimal", intent: "info", class: "text-info-text" },

      // ── outline: hairline chip, no fill (neutral tag / hued marker) ───────
      {
        variant: "outline",
        intent: "default",
        class: "border-border text-foreground",
      },
      {
        variant: "outline",
        intent: "success",
        class: "border-success/(--alpha-outline-border) text-success-text",
      },
      {
        variant: "outline",
        intent: "warning",
        class: "border-warning/(--alpha-outline-border) text-warning-text",
      },
      {
        variant: "outline",
        intent: "destructive",
        class:
          "border-destructive/(--alpha-outline-border) text-destructive-text",
      },
      {
        variant: "outline",
        intent: "info",
        class: "border-info/(--alpha-outline-border) text-info-text",
      },

      // ── bordered subtle: tint fill + matching-hue border (Attio chip formula)
      {
        variant: "subtle",
        bordered: true,
        intent: "default",
        class: "border-border",
      },
      {
        variant: "subtle",
        bordered: true,
        intent: "success",
        class: "border-success/(--alpha-outline-border)",
      },
      {
        variant: "subtle",
        bordered: true,
        intent: "warning",
        class: "border-warning/(--alpha-outline-border)",
      },
      {
        variant: "subtle",
        bordered: true,
        intent: "destructive",
        class: "border-destructive/(--alpha-outline-border)",
      },
      {
        variant: "subtle",
        bordered: true,
        intent: "info",
        class: "border-info/(--alpha-outline-border)",
      },
    ],
    defaultVariants: {
      variant: "subtle",
      intent: "default",
      size: "default",
      bordered: false,
    },
  },
);

/** Dot size per badge size — the indicator scales with the badge. */
const dotSize: Record<
  NonNullable<VariantProps<typeof badgeVariants>["size"]>,
  string
> = {
  sm: "size-1.5",
  default: "size-1.5",
  lg: "size-2",
};

/** Dot color per `intent` family. `solid` uses the on-color foreground instead. */
const dotColor: Record<
  NonNullable<VariantProps<typeof badgeVariants>["intent"]>,
  string
> = {
  default: "bg-muted-foreground",
  success: "bg-success",
  warning: "bg-warning",
  destructive: "bg-destructive",
  info: "bg-info",
};

/** Props accepted by `Badge`. */
export interface BadgeProps
  extends
    React.ComponentPropsWithRef<"span">,
    VariantProps<typeof badgeVariants> {
  /**
   * Visual treatment.
   * - `subtle`: soft `{family}-subtle` tint + `{family}-text` (default).
   * - `solid`: family fill with on-color text.
   * - `minimal`: borderless, no background — colored text only.
   * - `outline`: hairline chip, no fill — the neutral/hued tag treatment.
   * @default 'subtle'
   */
  variant?: "subtle" | "solid" | "minimal" | "outline";
  /**
   * Semantic intent family. Maps to design-system tokens only — never an
   * arbitrary hex or `color-mix` value. `default` is the neutral `muted` badge.
   * @default 'default'
   */
  intent?: "default" | "success" | "warning" | "destructive" | "info";
  /**
   * Size variant — pills sit at the `h-5` badge height (`lg` roomier `h-6`).
   * @default 'default'
   */
  size?: "sm" | "default" | "lg";
  /**
   * Draw the matching-hue hairline border on the `subtle` tint (the crisp
   * "chip" read on white surfaces). No-op on other variants.
   * @default false
   */
  bordered?: boolean;
  /**
   * Show a small leading dot indicator colored by `intent`. Ignored while
   * `loading`. Mutually exclusive with a leading icon.
   * @default false
   */
  dot?: boolean;
  /**
   * Replace the leading content with a spinner and set `aria-busy`. Takes
   * precedence over `dot` and any leading icon.
   * @default false
   */
  loading?: boolean;
  /**
   * Opt-in mount animation (`motion-pop-in`, a scale + fade "arrival") for a
   * badge that appears in response to a real event — e.g. a status that just
   * flipped to `"Verified"`, a freshly-applied label, or a badge toggled on by
   * a user action. **Default off**: a badge rendered as part of a static list
   * (a table column, a filter chip row) must not pop every time its parent
   * re-renders or mounts. Set it only where the badge's own appearance IS the
   * signal.
   * @default false
   */
  animateIn?: boolean;
  /**
   * Replace the rendered element via Base UI `render` composition. Pass a
   * `ReactElement` or a render function.

   * @default undefined
   */
  render?: useRender.RenderProp;
}

/**
 * `Badge` — a compact `rounded-full` status / label chip. Four variants
 * (`subtle`, `solid`, `minimal`, `outline`) × five semantic intents × three sizes, with an
 * optional leading `dot`, a `loading` spinner, and leading icons composed as
 * `children`. Purely presentational; use Base UI `render` to compose with a link.
 * Pass `animateIn` to pop the badge in on mount — off by default so static lists
 * of badges stay still.
 *
 * @example
 * <Badge intent="success" dot>Active</Badge>
 */
export function Badge({
  className,
  variant = "subtle",
  intent = "default",
  size = "default",
  bordered = false,
  dot = false,
  loading = false,
  animateIn = false,
  render,
  children,
  ref,
  ...props
}: BadgeProps) {
  const showDot = dot && !loading;
  const dotClass =
    variant === "solid" ? "bg-current" : dotColor[intent ?? "default"];

  return useRender({
    render: render ?? <span />,
    defaultTagName: "span",
    ref, // forward the consumer ref onto the rendered (or composed) element
    props: {
      "data-slot": "badge",
      "data-variant": variant,
      "data-intent": intent,
      "data-size": size,
      "data-bordered": bordered ? "" : undefined,
      "data-loading": loading ? "" : undefined,
      "aria-busy": loading || undefined,
      className: cn(
        badgeVariants({ variant, intent, size, bordered }),
        animateIn && "motion-pop-in",
        className,
      ),
      children: (
        <>
          {loading ? (
            <Spinner
              size="inherit"
              label=""
              className="size-(--icon-compact)"
            />
          ) : showDot ? (
            <span
              className={cn(
                "shrink-0 rounded-full",
                dotSize[size ?? "default"],
                dotClass,
              )}
              aria-hidden
            />
          ) : null}
          {children}
        </>
      ),
      ...props,
    },
  });
}

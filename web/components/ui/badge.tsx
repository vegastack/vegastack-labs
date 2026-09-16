"use client";

import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { useRender } from "@base-ui/react/use-render";
import { Spinner } from "@/components/ui/spinner";
import { cn } from "@vegastack/design";

/**
 * Badge variants — `variant` (solid / soft / outline / minimal) × `intent` (semantic
 * family) × `size`. The variant vocabulary is the system's, shared with Button.
 * Badges are `rounded-full` pills: the default `soft` treatment uses a
 * `{family}-subtle` tint + `{family}-text`, `solid` uses the family fill +
 * on-color foreground, `outline` is a fill-less hairline chip, and `minimal` is
 * ink only — no fill, no border, no horizontal padding, so it sits flush in a
 * table cell (audit D8). The neutral badge resolves to `muted`. Every value is a
 * semantic Tailwind token (no hardcoded colors, no `color-mix`, no inline
 * styles); tinting per family is expressed via compound variants.
 */
export const badgeVariants = cva(
  // text-ellipsis makes a consumer-supplied max-w-* cap elide instead of hard-clipping —
  // costless at the default w-fit (content never overflows itself).
  "inline-flex w-fit shrink-0 items-center justify-center gap-1 overflow-hidden rounded-full border border-transparent text-ellipsis whitespace-nowrap [&_svg]:pointer-events-none [&_svg]:shrink-0",
  {
    variants: {
      variant: {
        soft: "border-transparent",
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
       * Matching-hue border on the `soft` tint (Wave 2 — the Attio chip
       * formula: tint fill + same-hue border + family text). No-op on other
       * variants; `outline` already carries its border.
       */
      bordered: {
        true: "",
        false: "",
      },
      size: {
        // `sm` is a REAL 16px tier (audit D8), not `md` with 2px less padding: it is the
        // dense-table chip. `leading-none` keeps the 12px label inside a 16px box.
        sm: "h-4 gap-1 px-1.5 text-label-sm leading-none [&_svg:not([class*='size-'])]:size-(--icon-compact)",
        md: "h-5 gap-1 px-2 py-0.5 text-label-sm [&_svg:not([class*='size-'])]:size-(--icon-compact)",
        lg: "h-6 gap-1 px-2.5 py-0.5 text-label-sm [&_svg:not([class*='size-'])]:size-(--icon-inline)",
      },
    },
    compoundVariants: [
      // ── soft: {family}-subtle tint + {family}-text (the default) ──────────
      {
        variant: "soft",
        intent: "default",
        class: "bg-muted text-muted-foreground",
      },
      {
        variant: "soft",
        intent: "success",
        class: "bg-success-subtle text-success-text",
      },
      {
        variant: "soft",
        intent: "warning",
        class: "bg-warning-subtle text-warning-text",
      },
      {
        variant: "soft",
        intent: "destructive",
        class: "bg-destructive-subtle text-destructive-text",
      },
      {
        variant: "soft",
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

      // ── minimal: ink only — no fill, no border, no pill padding (audit D8) ─
      // `px-0` lives on a compound so it lands AFTER the `size` variant's padding
      // (cva emits base, then variants in key order, then compounds).
      {
        variant: "minimal",
        intent: "default",
        class: "px-0 text-muted-foreground",
      },
      {
        variant: "minimal",
        intent: "success",
        class: "px-0 text-success-text",
      },
      {
        variant: "minimal",
        intent: "warning",
        class: "px-0 text-warning-text",
      },
      {
        variant: "minimal",
        intent: "destructive",
        class: "px-0 text-destructive-text",
      },
      { variant: "minimal", intent: "info", class: "px-0 text-info-text" },

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

      // ── bordered soft: tint fill + matching-hue border (Attio chip formula)
      {
        variant: "soft",
        bordered: true,
        intent: "default",
        class: "border-border",
      },
      {
        variant: "soft",
        bordered: true,
        intent: "success",
        class: "border-success/(--alpha-outline-border)",
      },
      {
        variant: "soft",
        bordered: true,
        intent: "warning",
        class: "border-warning/(--alpha-outline-border)",
      },
      {
        variant: "soft",
        bordered: true,
        intent: "destructive",
        class: "border-destructive/(--alpha-outline-border)",
      },
      {
        variant: "soft",
        bordered: true,
        intent: "info",
        class: "border-info/(--alpha-outline-border)",
      },
    ],
    defaultVariants: {
      variant: "soft",
      intent: "default",
      size: "md",
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
  md: "size-1.5",
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
   * Visual treatment — the system's variant vocabulary, shared with Button.
   * - `solid`: family fill with on-color text.
   * - `soft`: `{family}-subtle` tint + `{family}-text` (default).
   * - `outline`: hairline chip, no fill — the neutral/hued tag treatment.
   * - `minimal`: ink only — no fill, no border, no horizontal padding, and a
   *   leading dot by default so status is never signalled by colour alone.
   * @default 'soft'
   */
  variant?: "solid" | "soft" | "outline" | "minimal";
  /**
   * Semantic intent family. Maps to design-system tokens only — never an
   * arbitrary hex or `color-mix` value. `default` is the neutral `muted` badge.
   * @default 'default'
   */
  intent?: "default" | "success" | "warning" | "destructive" | "info";
  /**
   * Size tier — three real heights: `sm` 16px (dense tables), `md` 20px, `lg`
   * 24px. The dot and any composed icon scale with the badge.
   * @default 'md'
   */
  size?: "sm" | "md" | "lg";
  /**
   * Draw the matching-hue hairline border on the `soft` tint (the crisp
   * "chip" read on white surfaces). No-op on other variants.
   * @default false
   */
  bordered?: boolean;
  /**
   * Show a small leading dot indicator colored by `intent`. Ignored while
   * `loading`, and replaced by `icon` when one is given.
   *
   * Defaults to `true` on `variant="minimal"` and `false` everywhere else: a
   * minimal badge has no container, so the dot is the only non-colour carrier of
   * its status (WCAG 1.4.1). Pass `dot={false}` to opt a minimal badge out.
   * @default undefined
   */
  dot?: boolean;
  /**
   * Leading icon, rendered in the dot's place. Pass a `lucide-react` element
   * (or `Icon`) — it is sized by the badge's own `[&_svg]` rule, so do not set
   * `size` on it. Ignored while `loading`.

   * @default undefined
   */
  icon?: React.ReactNode;
  /**
   * Replace the leading content with a spinner and set `aria-busy`. Takes
   * precedence over `icon` and `dot`.
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
 * `Badge` — a compact status / label chip. Four variants (`solid`, `soft`,
 * `outline`, `minimal`) × five semantic intents × three real size tiers (16 / 20 /
 * 24px), with a leading `dot`, a leading `icon` in the dot's place, and a
 * `loading` spinner. Purely presentational; use Base UI `render` to compose with a
 * link. Pass `animateIn` to pop the badge in on mount — off by default so static
 * lists of badges stay still.
 *
 * `minimal` is the container-less treatment for dense tables: coloured ink, no
 * pill, and a leading dot by default (audit D8). Everything else is a pill at
 * `rounded-full`.
 *
 * @example
 * <Badge intent="success" dot>Active</Badge>
 *
 * @example
 * // dense table cell — ink only, dot carries the status
 * <Badge variant="minimal" intent="warning" size="sm">Pending</Badge>
 *
 * @example
 * // an icon takes the dot's place
 * <Badge variant="minimal" intent="success" icon={<CircleCheck />}>Paid</Badge>
 */
export function Badge({
  className,
  variant = "soft",
  intent = "default",
  size = "md",
  bordered = false,
  dot,
  icon,
  loading = false,
  animateIn = false,
  render,
  children,
  ref,
  ...props
}: BadgeProps) {
  // A minimal badge has no container, so its dot is the one non-colour status
  // carrier — on by default there, off everywhere else. An explicit `dot` always wins.
  const showDot = (dot ?? variant === "minimal") && !loading && icon == null;
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
      "data-dot": showDot ? "" : undefined,
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
          ) : icon != null ? (
            <span className="shrink-0" aria-hidden>
              {icon}
            </span>
          ) : showDot ? (
            <span
              className={cn(
                "shrink-0 rounded-full",
                dotSize[size ?? "md"],
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

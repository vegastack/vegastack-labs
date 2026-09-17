"use client";

import * as React from "react";
import { useRender } from "@base-ui/react/use-render";
import { X } from "lucide-react";
import { cn } from "@vegastack/design";
import { IconButton } from "@/components/ui/icon-button";

/* ------------------------------------------------------------------------------------------------
 * Chip — THE pill primitive (audit 2026-09-07, B5-03 / 04-cross-cutting §1).
 *
 * Before this file there were four recipes for "a labelled, optionally removable pill": `Tag`
 * (a `::before` hit area on a bare button), `FilterChip` (a real 24px box with twenty lines of
 * margin arithmetic explaining itself), `ComboboxChip` + `ComboboxChipRemove` (a bare 16px box with
 * NO hit-area expansion at all — a WCAG 2.5.8 failure), and ChipInput's chip. They disagreed on
 * height, radius, rest fill and — the part that actually hurt users — on how big the remove control
 * was. All four now compose this one primitive through Base UI `render`, so the geometry, the
 * hover/pressed grammar and the 24px remove target are spelled exactly once.
 *
 * `Badge bordered` deliberately did NOT fold in: a Badge is the STATUS voice (semantic intent, never
 * removable), a Chip is the LABEL/SELECTION voice. Same shape, different job.
 * ----------------------------------------------------------------------------------------------*/

/**
 * Chip hues — the 10-hue decorative `--tag-*` palette plus the neutral chip. Decorative labelling
 * only; a status signal is `Badge`'s job.
 */
export type ChipHue =
  | "neutral"
  | "blue"
  | "cyan"
  | "green"
  | "lime"
  | "yellow"
  | "orange"
  | "red"
  | "pink"
  | "magenta"
  | "purple";

/** The two chip tiers, on the one `--size-*` control vocabulary. */
export type ChipSize = "sm" | "md";

/**
 * The chromatic hue formula (both themes, AA-gated in `contrast-check.mjs`): `tag-{hue}-subtle`
 * fill + `tag-{hue}-text` ink + a hairline of the hue's ink at the outline alpha. The neutral chip
 * is the surface ladder instead: rung 1 is a filled control's rest fill (`design.md` §Surface
 * ladder), and `active` promotes it to rung 2 — the selection rung — so an applied filter reads as
 * a selection without borrowing a hue.
 *
 * Static class literals per hue, so the Tailwind scanner sees every string.
 */
const HUE_CLASSES: Record<ChipHue, string> = {
  neutral: "border-border bg-surface-1 text-foreground",
  blue: "border-tag-blue-text/(--alpha-outline-border) bg-tag-blue-subtle text-tag-blue-text",
  cyan: "border-tag-cyan-text/(--alpha-outline-border) bg-tag-cyan-subtle text-tag-cyan-text",
  green:
    "border-tag-green-text/(--alpha-outline-border) bg-tag-green-subtle text-tag-green-text",
  lime: "border-tag-lime-text/(--alpha-outline-border) bg-tag-lime-subtle text-tag-lime-text",
  yellow:
    "border-tag-yellow-text/(--alpha-outline-border) bg-tag-yellow-subtle text-tag-yellow-text",
  orange:
    "border-tag-orange-text/(--alpha-outline-border) bg-tag-orange-subtle text-tag-orange-text",
  red: "border-tag-red-text/(--alpha-outline-border) bg-tag-red-subtle text-tag-red-text",
  pink: "border-tag-pink-text/(--alpha-outline-border) bg-tag-pink-subtle text-tag-pink-text",
  magenta:
    "border-tag-magenta-text/(--alpha-outline-border) bg-tag-magenta-subtle text-tag-magenta-text",
  purple:
    "border-tag-purple-text/(--alpha-outline-border) bg-tag-purple-subtle text-tag-purple-text",
};

/** The neutral chip's selection rung — rung 2, the same step every selected surface takes. */
const ACTIVE_NEUTRAL = "border-border bg-surface-2 text-foreground";

/**
 * Two tiers only. `sm` (28px) is the INLINE tag tier — Tag, ChipInput's chips, Combobox's selected
 * values; `md` (32px) is the standalone control tier — FilterBar's applied filters, which sit in a
 * row of 32px controls and must line up with them.
 *
 * The end padding is asymmetric on purpose: the remove control is a real 24×24 box (WCAG 2.5.8),
 * so the trailing edge only needs the gap left over after it, while the leading edge carries the
 * label's own optical padding.
 */
const SIZE_CLASSES: Record<ChipSize, string> = {
  sm: "h-(--size-sm) gap-1 ps-2 pe-0.5 text-label-sm [&_svg:not([class*='size-'])]:size-(--icon-compact)",
  md: "h-(--size-md) gap-1 ps-2.5 pe-1 text-label [&_svg:not([class*='size-'])]:size-(--icon-inline)",
};

/** Props accepted by `Chip`. */
export interface ChipProps extends Omit<
  React.ComponentPropsWithRef<"span">,
  "children"
> {
  /**
   * Decorative hue from the tag palette. Never a status signal — that is `Badge`.
   * @default 'neutral'
   */
  hue?: ChipHue;
  /**
   * Tier. `sm` is the inline tag tier (28px); `md` is the standalone control tier (32px)
   * that lines up with Buttons and Inputs.
   * @default 'sm'
   */
  size?: ChipSize;
  /**
   * Marks the chip as an applied selection — the neutral chip takes the selection rung
   * (`surface-2`) instead of its rest fill. Ignored for chromatic hues, whose tint already
   * carries the meaning.
   * @default false
   */
  active?: boolean;
  /**
   * Render a remove affordance and call this when it is activated. The control is a real
   * 24×24 `IconButton`, never a pseudo-element hit area.
   * @default undefined
   */
  onRemove?: () => void;
  /**
   * Accessible name for the remove control. Always name what is being removed.
   * @default 'Remove'
   */
  removeLabel?: string;
  /**
   * Replace the rendered `<span>` via Base UI `render` composition — how `ComboboxChip`
   * puts this geometry on Base UI's own `Combobox.Chip`.
   * @default undefined
   */
  render?: useRender.RenderProp;
  /**
   * The chip's content, laid out as a flex row. A part that can grow unboundedly is the
   * caller's to wrap: `<span className="min-w-0 truncate">` — Chip cannot know which of
   * several children should give way.
   * @default undefined
   */
  children?: React.ReactNode;
  /**
   * Slot marker, for wrappers that compose Chip and want their own generated registry slot.
   * @default 'chip'
   */
  "data-slot"?: string;
}

/**
 * `Chip` — one labelled pill, optionally removable. The primitive behind `Tag`, `FilterChip`,
 * `ComboboxChip` and ChipInput's chips.
 *
 * The chip itself is NOT interactive: it has no hover or pressed step, because nothing happens when
 * you click it. The remove control is the interactive part and it carries the full grammar — hover
 * climbs the surface ladder, pressing climbs one more — from the `ghost` `IconButton` it composes.
 *
 * @example
 * <Chip hue="blue" onRemove={() => remove("API")} removeLabel="Remove API">API</Chip>
 * @example
 * <Chip size="md" active onRemove={clearStatus} removeLabel="Remove Status filter">
 *   Status: Active
 * </Chip>
 */
export function Chip({
  className,
  hue = "neutral",
  size = "sm",
  active = false,
  onRemove,
  removeLabel,
  render,
  children,
  ref,
  "data-slot": dataSlot,
  ...props
}: ChipProps) {
  return useRender({
    render: render ?? <span />,
    defaultTagName: "span",
    ref,
    props: {
      "data-slot": dataSlot ?? "chip",
      "data-hue": hue,
      "data-size": size,
      "data-active": active ? "" : undefined,
      className: cn(
        "inline-flex w-fit max-w-full min-w-0 shrink-0 items-center rounded-full border whitespace-nowrap",
        "[&_svg]:pointer-events-none [&_svg]:shrink-0",
        SIZE_CLASSES[size],
        active && hue === "neutral" ? ACTIVE_NEUTRAL : HUE_CLASSES[hue],
        "data-[disabled]:pointer-events-none data-[disabled]:opacity-(--opacity-dim)",
        className,
      ),
      children: (
        <>
          {children}
          {onRemove ? (
            <ChipRemove
              aria-label={removeLabel ?? "Remove"}
              onClick={onRemove}
            />
          ) : null}
        </>
      ),
      ...props,
    },
  });
}

/** Props accepted by `ChipRemove`. */
export type ChipRemoveProps = React.ComponentProps<typeof IconButton>;

/**
 * `ChipRemove` — the trailing `×` on a {@link Chip}. A round, ghost, 24×24 `IconButton`: the real
 * border box IS the WCAG 2.5.8 target, so no invisible `::before` expansion is involved and nothing
 * can clip it. (`Tag`'s old pseudo-element hit area silently failed to expand anything at all —
 * Preflight's `appearance: button` clips generated content to a nested `<button>`'s own border box,
 * so the pseudo computed correctly but was never hit-testable.)
 *
 * Exported so a chip whose remove control belongs to another engine can wear this geometry through
 * `render` — that is exactly what `ComboboxChipRemove` does with Base UI's `Combobox.ChipRemove`.
 *
 * @example
 * <ChipRemove aria-label="Remove Design" onClick={remove} />
 * @example
 * <ChipRemove aria-label="Remove Design" render={<Combobox.ChipRemove />} />
 */
export function ChipRemove({
  className,
  children,
  "data-slot": dataSlot,
  ...props
}: ChipRemoveProps) {
  return (
    <IconButton
      variant="ghost"
      size="xs"
      shape="round"
      data-slot={dataSlot ?? "chip-remove"}
      className={cn("shrink-0", className)}
      {...props}
    >
      {children ?? <X className="size-(--icon-compact)" aria-hidden />}
    </IconButton>
  );
}

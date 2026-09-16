"use client";

import * as React from "react";
import { Minus, Plus } from "lucide-react";
import { NumberField as BaseNumberField } from "@base-ui/react/number-field";
import {
  cn,
  fieldControlGroup,
  surfaceInteractiveGroup,
} from "@vegastack/design";

/* ---
`NumberField` exists because the roster had no numeric input at all: quantities, limits,
percentages and money were all being typed into a text `Input` with hand-rolled parsing.
Base UI's NumberField supplies the hard parts — locale-aware parsing/formatting
(`format: Intl.NumberFormatOptions` + `locale`), min/max/step with snap, keyboard
stepping, wheel scrub — so this wrapper's job is chrome: Input's exact addon-group
visual (border, focus tint, invalid, disabled, dark input wash, the 28/32/40 size
scale) with full-height stepper buttons.

Money is a format prop, not a component: pass
`format={{ style: "currency", currency: "INR" }}`. A CRM-specific `money-input` in a
general design system is the wrong shape (scope call S4). Minor-units conversion (cents
in the API, display units here) belongs at the app's field layer — documented on the
docs page, deliberately not built in.

Deliberately NOT done here:
- No `ScrubArea`. Pointer-scrubbing on a label is a power affordance with no keyboard
  or touch equivalent; consumers who want it compose `BaseNumberField.ScrubArea`
  directly inside a custom `prefix`.
- No native `size` attribute. Like `Input`, the `size` prop is the control-height
  variant (`--size-sm/md/lg`) and deliberately replaces the numeric HTML attribute.
- No re-exposed `Group` part. The root IS the bordered group here; splitting parts
  would only invite layouts the chrome cannot honour.
--- */

/** Props accepted by `NumberField`. */
export interface NumberFieldProps extends Omit<
  React.ComponentProps<typeof BaseNumberField.Root>,
  "className" | "prefix"
> {
  /**
   * Control height on the shared 28/32/40 scale (`--size-sm/md/lg`), matching
   * `Input`/Button/Select. (The native numeric `size` attribute is intentionally
   * replaced by this variant prop, exactly as on `Input`.)
   * @default 'md'
   */
  size?: "sm" | "md" | "lg";
  /**
   * Accessible name for the numeric input. Required in practice unless a
   * wrapping `Field`/`aria-labelledby` supplies one — the input must never be
   * unnamed.

   * @default undefined
   */
  "aria-label"?: string;
  /**
   * Placeholder for the empty input.

   * @default undefined
   */
  placeholder?: string;
  /**
   * Non-editable addon before the input (a unit, an icon, a currency code) —
   * `Input`'s addon idiom. Plain strings render as muted, non-selectable text.

   * @default undefined
   */
  prefix?: React.ReactNode;
  /**
   * Non-editable addon after the input. The documented seat for a currency-code
   * `Select` in the money recipe.

   * @default undefined
   */
  suffix?: React.ReactNode;
  /**
   * Hide the − / + stepper buttons. Keyboard stepping (arrows, Home/End) and
   * wheel scrub keep working — the buttons are a pointer affordance only.
   * @default false
   */
  hideControls?: boolean;
  /** Extra classes for the bordered group root.
   * @default undefined
   */
  className?: string;
  /**
   * Classes for the inner `<input>` element (e.g. `text-end` for columnar
   * numbers).

   * @default undefined
   */
  inputClassName?: string;
  /**
   * Ref forwarded to the inner `<input>` element.

   * @default undefined
   */
  inputRef?: React.Ref<HTMLInputElement>;
}

/**
 * Group layout only. The border, focus tint, invalid tint, disabled wash and dark input tint
 * are `fieldControlGroup` — the one wrapper recipe `Input`'s addon mode, ChipInput and the
 * Combobox input-group also wear (audit B1-11), so the four can no longer drift apart.
 * `data-field-group` on the root is what lets `base.css` paint the forced-colours focus outline
 * on the GROUP instead of on the inner input, whose own outline this `overflow-hidden` clips.
 */
const groupClasses =
  "flex w-full min-w-0 items-center overflow-hidden text-base";

const sizeClasses = {
  sm: "h-(--size-sm) text-sm",
  md: "h-(--size-md)",
  lg: "h-(--size-lg)",
} as const;

/**
 * Addon-slot classes — `Input`'s, plus the rules an INTERACTIVE addon needs. The suffix slot is
 * the documented seat for the money recipe's currency `Select` (see `suffix`), and a pressable
 * control dropped in there inherited two defects the steppers had already been fixed for
 * (appearance probe 2026-09-07, SP-02/SP-03 residue):
 *
 *   - its hover wash ran flush into the field's top and bottom hairlines — a `sm` trigger is 28px
 *     inside a 30px inner box, so the wash sat 1px off the rule and read as a rendering bug;
 *   - its `:focus-visible` outline is drawn OUTSIDE its box, and the root is `overflow-hidden`,
 *     so the ring was clipped away on both edges.
 *
 * Both are fixed here rather than at each call site, because the slot is what knows it lives
 * inside a clipping, hairlined group: the span stretches to the full inner height, insets its
 * content by 4px (design.md's hover-geometry floor), and hands a button child the inner radius
 * and the sanctioned negative outline offset. A text or icon addon is untouched — the rules are
 * scoped to a `button` child.
 */
// `join(" ")`, not `+`: a trailing space inside a concatenated string literal is invisible to the
// reader and removable by a formatter, and when one goes the two class names weld into a token
// Tailwind never compiles and nothing errors on (commit b2c2e964 did exactly that to four sites in
// this repo). An array cannot be broken that way.
const addonClasses = [
  "flex shrink-0 self-stretch items-center py-1 text-muted-foreground select-none whitespace-nowrap",
  "[&>button]:relative [&>button]:h-full [&>button]:rounded-sm [&>button]:focus-visible:-outline-offset-2",
  // The 4px inset leaves a 22px control in an `md` field, under the 24px pointer floor — the two
  // rules cannot both be paid for out of 32px of height. So the PAINT is inset and the TARGET is
  // not: the standard invisible hit area gives the control back the 4px it just gave up, exactly
  // as `RelativeTime`, `Marker` and `Switch` do. It reaches into this slot's own padding, so the
  // root's `overflow-hidden` never clips it (a clipped area stops being hit-testable — see the
  // `timeline` entry in the bugs ledger).
  "[&>button]:before:absolute [&>button]:before:inset-x-0 [&>button]:before:-inset-y-1 [&>button]:before:content-['']",
].join(" ");

/**
 * Full-height stepper buttons flanking the field ([−] input [+]): each is the
 * control's full height and ≥ 24px wide, so the pointer targets meet WCAG 2.5.8
 * without a hit-area expansion — unlike the traditional half-height stacked
 * spinners, which cannot. They keep the centralized `:focus-visible` outline
 * (never `outline-none` — P0-02) with the sanctioned negative offset so the
 * root's `overflow-hidden` cannot clip it.
 */
const stepperClasses = [
  "group/wash flex h-full w-(--size-sm) shrink-0 items-center justify-center p-1 text-muted-foreground",
  "hover:text-foreground",
  "focus-visible:-outline-offset-2",
  "disabled:opacity-(--opacity-dim)",
  "data-disabled:opacity-(--opacity-dim)",
].join(" ");

/**
 * The stepper's wash is an INSET CHIP inside the button, never the button's own background
 * (audit SP-02). Full-bleed `hover:bg-surface-2` ran the fill flush into the field's hairline on
 * three sides and met the rounded outer corner with a square one; `design.md`'s hover-geometry
 * rule ("a wash is inset ≥4px from a container hairline and inherits its inner radius") exists
 * because of exactly this defect. `p-1` on the button insets the chip by 4px and `rounded-sm`
 * gives it a corner of its own, so a 28×32 stepper hovers as a 20×24 chip. The button keeps the
 * full pointer target and the ink step; only the paint moved inward.
 *
 * The two rungs themselves are NOT written here: `surfaceInteractiveGroup` is the group-scoped
 * twin of `@vegastack/design`'s `surfaceInteractive`, so this chip climbs the same ladder as every
 * other transparent control and retuning the ladder is still one edit.
 */
const stepperFillClasses = cn(
  "flex size-full items-center justify-center rounded-sm",
  surfaceInteractiveGroup,
  "group-disabled/wash:bg-transparent group-data-disabled/wash:bg-transparent",
);

/**
 * `NumberField` — a locale-aware numeric input on Base UI's NumberField, in
 * `Input`'s exact field chrome. Formatting is `Intl`: pass
 * `format={{ style: "percent" }}`, `{ style: "currency", currency: "EUR" }`,
 * or unit options, plus `locale` to pin one. `min`/`max`/`step` (with
 * `snapOnStep`), keyboard stepping (arrows; <kbd>Shift</kbd> for `largeStep`,
 * <kbd>Alt</kbd> for `smallStep`), and wheel scrubbing all come from Base UI.
 *
 * Money is a recipe, not a separate component: currency `format` here, and the
 * app's field layer converts integer minor units (cents) to display units.
 *
 * @example
 * <NumberField aria-label="Quantity" defaultValue={2} min={0} max={99} />
 *
 * @example
 * // Money
 * <NumberField
 *   aria-label="Amount"
 *   format={{ style: "currency", currency: "USD" }}
 *   min={0}
 *   step={0.01}
 * />
 */
export function NumberField({
  size = "md",
  "aria-label": ariaLabel,
  placeholder,
  prefix,
  suffix,
  hideControls = false,
  className,
  inputClassName,
  inputRef,
  ...rootProps
}: NumberFieldProps) {
  return (
    <BaseNumberField.Root
      data-slot="number-field"
      data-size={size}
      data-field-group=""
      className={cn(
        fieldControlGroup,
        groupClasses,
        sizeClasses[size],
        className,
      )}
      {...rootProps}
    >
      {hideControls ? null : (
        <BaseNumberField.Decrement
          data-slot="number-field-decrement"
          aria-label="Decrease"
          className={cn(stepperClasses, "border-e border-input")}
        >
          <span className={stepperFillClasses}>
            <Minus className="size-(--icon-compact)" aria-hidden />
          </span>
        </BaseNumberField.Decrement>
      )}
      {prefix != null ? (
        <span
          data-slot="number-field-prefix"
          className={cn(addonClasses, "ps-3")}
        >
          {prefix}
        </span>
      ) : null}
      <BaseNumberField.Input
        ref={inputRef}
        data-slot="number-field-input"
        aria-label={ariaLabel}
        placeholder={placeholder}
        className={cn(
          "h-full w-full min-w-0 flex-1 bg-transparent py-1 text-inherit outline-hidden",
          "placeholder:text-muted-foreground-faint",
          "disabled:cursor-not-allowed",
          prefix != null ? "ps-1.5" : "ps-3",
          suffix != null ? "pe-1.5" : "pe-3",
          inputClassName,
        )}
      />
      {suffix != null ? (
        <span
          data-slot="number-field-suffix"
          className={cn(addonClasses, "pe-3")}
        >
          {suffix}
        </span>
      ) : null}
      {hideControls ? null : (
        <BaseNumberField.Increment
          data-slot="number-field-increment"
          aria-label="Increase"
          className={cn(stepperClasses, "border-s border-input")}
        >
          <span className={stepperFillClasses}>
            <Plus className="size-(--icon-compact)" aria-hidden />
          </span>
        </BaseNumberField.Increment>
      )}
    </BaseNumberField.Root>
  );
}

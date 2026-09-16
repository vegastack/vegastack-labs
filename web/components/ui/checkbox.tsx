"use client";

import * as React from "react";
import { Checkbox as BaseCheckbox } from "@base-ui/react/checkbox";
import { cva, type VariantProps } from "class-variance-authority";
import { Check, Minus } from "lucide-react";
import { cn } from "@vegastack/design";

/**
 * Checkbox variants. `size` mirrors the form-control scale so checkboxes line up
 * with sibling inputs and switches: `md` (size-4) and `sm` (size-3.5).
 * The checked/indeterminate state fills with neutral `primary` ink;
 * every value is a semantic token (no hardcoded colors or sizes).
 *
 * Both visual boxes (16px / 14px) are smaller than the WCAG 2.5.8 24×24 CSS px
 * minimum target size, so each size adds an invisible `::before` hit-area
 * expansion (`relative` + `before:absolute before:-inset-*`, already-transparent
 * generated content) sized to bring the EFFECTIVE hit area to ≥24×24 without
 * touching the visible box. The 1px border means the pseudo-element is positioned
 * from a 14px/12px padding box, so both sizes use a 6px inset: 26px / 24px.
 */
export const checkboxVariants = cva(
  [
    "peer relative inline-flex shrink-0 items-center justify-center rounded-sm border border-input bg-transparent text-current",
    "dark:bg-input/(--alpha-input)",
    // Hover is the SAME neutral border rung every field wears (`fieldControl`'s
    // `--alpha-border-subtle`), not the `ring` tint — `ring` is reserved for focus, and a
    // checkbox sitting beside an Input must not hover in a different language (audit SP-04).
    "not-disabled:hover:border-foreground/(--alpha-border-subtle)",
    "data-checked:border-primary data-checked:bg-primary data-checked:text-primary-foreground",
    "data-indeterminate:border-primary data-indeterminate:bg-primary data-indeterminate:text-primary-foreground",
    // …and once it is FILLED the neutral tint has nothing to tint, so the checked box steps
    // through the solid's own darker rungs instead — the doctrine's "a solid fill does not use
    // the alpha twins" rule. F1 left this half undone; a ticked checkbox read dead under the
    // cursor while an unticked one moved.
    "not-disabled:data-checked:hover:border-primary-hover not-disabled:data-checked:hover:bg-primary-hover",
    "not-disabled:data-checked:active:border-primary-active not-disabled:data-checked:active:bg-primary-active",
    "not-disabled:data-indeterminate:hover:border-primary-hover not-disabled:data-indeterminate:hover:bg-primary-hover",
    "aria-invalid:border-destructive-border/(--alpha-tint-border) data-invalid:border-destructive-border/(--alpha-tint-border)",
    // D7: no `pointer-events-none`. A disabled control must stay hoverable so a Tooltip can
    // say why it is unavailable; Base UI suppresses the activation either way.
    "disabled:cursor-not-allowed disabled:opacity-(--opacity-dim)",
    "group-has-disabled/field:opacity-(--opacity-dim)",
  ].join(" "),
  {
    variants: {
      size: {
        md: "size-4 before:absolute before:-inset-1.5",
        sm: "size-3.5 before:absolute before:-inset-1.5",
      },
    },
    defaultVariants: { size: "md" },
  },
);

/** Props accepted by `Checkbox`. */
export interface CheckboxProps
  extends
    React.ComponentProps<typeof BaseCheckbox.Root>,
    VariantProps<typeof checkboxVariants> {
  /**
   * Whether the checkbox is ticked (controlled). Pair with `onCheckedChange`.
   * Use `defaultChecked` for an uncontrolled checkbox instead.
   * @default undefined
   */
  checked?: boolean;
  /**
   * Whether the checkbox is initially ticked (uncontrolled).
   * @default false
   */
  defaultChecked?: boolean;
  /**
   * Mixed state — neither ticked nor unticked. Renders the minus indicator and
   * sets `aria-checked="mixed"`. Typically derived from a group of children.
   * @default false
   */
  indeterminate?: boolean;
  /**
   * Called when the checkbox is ticked or unticked, with the next checked value.

   * @default undefined
   */
  onCheckedChange?: (
    checked: boolean,
    eventDetails: BaseCheckbox.Root.ChangeEventDetails,
  ) => void;
  /**
   * Prevent the user from changing the checkbox while still submitting its value.
   * @default false
   */
  disabled?: boolean;
  /**
   * Replace the rendered element via Base UI `render` composition. Pass a
   * `ReactElement` or a render function — Base UI merges this
   * wrapper's `className`, `data-slot`, and state `data-*` onto your element and
   * forwards the ref. The element must support `role="checkbox"` semantics.

   * @default undefined
   */
  render?: React.ComponentProps<typeof BaseCheckbox.Root>["render"];
}

/**
 * `Checkbox` — a binary (or tri-state) toggle built on
 * [Base UI Checkbox](https://base-ui.com/react/components/checkbox). Renders a
 * styled `<span>` plus a hidden `<input>`, with a lucide check/minus indicator.
 * Supports `checked`/`indeterminate`/`disabled`, full keyboard control
 * (<kbd>Space</kbd> toggles), and the centralized base.css `:focus-visible` outline (no ring of its own).
 *
 * Pair it with a label for accessibility — either inside a {@link Field} (which
 * auto-associates the label) or by passing an `aria-label` for a standalone
 * checkbox. For sibling `<label htmlFor>` patterns, follow Base UI's guidance
 * and pass `nativeButton render={<button />}` so the `id` targets a native
 * button root.
 *
 * @example
 * // Standalone, controlled
 * const [checked, setChecked] = React.useState(false);
 * <Checkbox checked={checked} onCheckedChange={setChecked} aria-label="Accept terms" />
 *
 * @example
 * // Inside a horizontal Field — label is auto-associated
 * <Field label="Subscribe to updates" orientation="horizontal">
 *   <Checkbox defaultChecked />
 * </Field>
 *
 * @example
 * // Indeterminate (mixed) "select all" state
 * <Checkbox indeterminate aria-label="Select all rows" />
 */
export function Checkbox({
  className,
  size = "md",
  ref,
  ...props
}: CheckboxProps) {
  return (
    <BaseCheckbox.Root
      ref={ref}
      data-slot="checkbox"
      data-size={size}
      className={cn(checkboxVariants({ size }), className)}
      {...props}
    >
      <BaseCheckbox.Indicator
        data-slot="checkbox-indicator"
        className={cn(
          "flex items-center justify-center text-current [&_svg]:shrink-0",
          size === "sm"
            ? "[&_svg]:size-(--icon-compact)"
            : "[&_svg]:size-(--icon-inline)",
        )}
      >
        {props.indeterminate ? (
          <Minus strokeWidth={2} aria-hidden />
        ) : (
          <Check strokeWidth={2} aria-hidden />
        )}
      </BaseCheckbox.Indicator>
    </BaseCheckbox.Root>
  );
}

import * as React from "react";
import { cn } from "@vegastack/design";

/**
 * Layout of the label box. `inline` is the default and the reason this prop exists (audit
 * B1-14): a `flex` label is a BLOCK, so a `<Label>` written inside a sentence — "Type the word
 * <Label>delete</Label> to confirm" — broke the line before and after itself, and no consumer
 * could fix it without overriding `display` by hand. `inline-flex` keeps the icon gap and the
 * baseline. `block` is the explicit opt-in for the stacked form-row case, where the label
 * should own its own full-width line.
 */
const layoutClasses = {
  inline: "inline-flex",
  block: "flex",
} as const;

/** Props accepted by `Label`. */
export interface LabelProps extends React.ComponentProps<"label"> {
  /**
   * Marks the labelled control as required by setting `data-required` on the
   * `<label>` (a styling/automation hook — no visual asterisk). Enforce
   * requiredness on the control itself (`required`) and surface it with an
   * inline `FieldError` on submit, not with a decorative mark.
   * @default false
   */
  required?: boolean;
  /**
   * Box layout. `inline` composes into running text and beside a control; `block` takes its own
   * full-width line above one.
   * @default 'inline'
   */
  layout?: keyof typeof layoutClasses;
}

/**
 * `Label` — a styled native `<label>` for form controls. Associate it with a
 * control via `htmlFor` (matching the control's `id`) or by wrapping the control
 * as a child. It is `inline-flex` by default so it composes into a sentence or sits beside a
 * control; pass `layout="block"` for the stacked form row. Dims to 50% opacity when the
 * labelled/peer control is disabled
 * (`peer-disabled:opacity-(--opacity-dim)`) or sits inside a disabled group
 * (`group-data-[disabled=true]:opacity-(--opacity-dim)`). Pass `required` to set a
 * `data-required` hook (no visual asterisk).
 *
 * Pure presentational and server-safe — no hooks, no `'use client'`. Forwards
 * its ref to the underlying `<label>`.
 *
 * @example
 * // Associated by htmlFor / id
 * <Label htmlFor="email" required>Email</Label>
 * <Input id="email" type="email" required />
 *
 * @example
 * // Wrapping the control
 * <Label>
 *   <Checkbox />
 *   Remember me
 * </Label>
 *
 * @example
 * // Stacked above a control
 * <Label layout="block" htmlFor="name">Full name</Label>
 * <Input id="name" />
 */
export function Label({
  className,
  required = false,
  layout = "inline",
  children,
  ref,
  ...props
}: LabelProps) {
  return (
    <label
      ref={ref}
      data-slot="label"
      data-layout={layout}
      data-required={required ? "" : undefined}
      className={cn(
        layoutClasses[layout],
        // 12px (audit D3): a form label is dense metadata about the control beneath it, not a
        // peer of the 14px value the user types into it. The doctrine moved to match.
        "items-center gap-2 text-label-sm text-foreground select-none",
        "peer-disabled:opacity-(--opacity-dim) peer-disabled:cursor-not-allowed",
        "group-data-[disabled=true]:opacity-(--opacity-dim) group-data-[disabled=true]:pointer-events-none",
        className,
      )}
      {...props}
    >
      {children}
    </label>
  );
}

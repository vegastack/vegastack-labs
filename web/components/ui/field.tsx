"use client";

import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { Field as BaseField } from "@base-ui/react/field";
import { cn, mergeRefs } from "@vegastack/design";
import { Input } from "@/components/ui/input";
import {
  useShakeOnInvalid,
  type ShakeSignal,
} from "@/components/ui/use-animation-replay";

/**
 * Field layout variants. `orientation` controls how the label sits relative to
 * the control: `vertical` stacks label-above-control (text inputs, selects),
 * `horizontal` places the control before an inline label (checkboxes, switches).
 * Every value is a semantic token (no hardcoded spacing colors).
 */
export const fieldVariants = cva("group/field flex w-full text-foreground", {
  variants: {
    orientation: {
      vertical: "flex-col gap-2",
      horizontal: "flex-row flex-wrap items-center gap-2",
      /** Vertical by default, horizontal from the `@md` width of the wrapping FieldGroup container. */
      responsive:
        "flex-col gap-2 @md/field-group:flex-row @md/field-group:flex-wrap @md/field-group:items-center",
    },
  },
  defaultVariants: { orientation: "vertical" },
});

/* ------------------------------------------------------------------------------------------------
 * Primitives — thin token-styled wrappers over Base UI Field parts. Each carries
 * a `data-slot` and forwards its ref. Base UI auto-wires `id`/`aria-describedby`/
 * `aria-invalid` across Root → Label → Control → Description → Error.
 * ----------------------------------------------------------------------------------------------*/

/** Props accepted by `FieldRoot`. */
export type FieldRootProps = React.ComponentProps<typeof BaseField.Root> &
  VariantProps<typeof fieldVariants> & {
    /**
     * Bump to a new value (e.g. a submit-attempt counter) to re-shake a field that is ALREADY
     * invalid. The field shakes itself once, automatically, the moment it BECOMES invalid; this
     * is only for a repeat failure against a field that never stopped being wrong.

     * @default undefined
     */
    shakeSignal?: ShakeSignal;
  };

/**
 * `FieldRoot` — groups all parts of a field, wires accessibility between them, and OWNS the
 * field's validation feedback. Renders a `<div>`. Use the prop-driven {@link Field} for the
 * common case; reach for the primitives when you need full control over composition.
 *
 * **The invalid shake lives here** (audit D5, 2026-09-07). It used to be wired into five
 * controls individually — Input, Checkbox, RadioGroupItem, OTPInput and NumberField each carried
 * the same `useShakeOnInvalid` + `mergeRefs` + `onAnimationEnd` plumbing, while `Textarea`, the
 * sibling of the first one, silently had none. One observer on the field root replaces all of
 * it: every control a `Field` wraps now reacts identically, whether or not its author remembered
 * to opt in. The whole field shakes as one block, label and message included — the field is what
 * the user got wrong, and moving the control alone under a still label read as a glitch.
 *
 * Base UI writes `data-invalid` onto this root, so the observer sees validity from `<Field
 * error=…>`, from a `validate` callback, and from native constraint validation alike — it never
 * has to be told. It fires only on a live valid→invalid transition, so a form rendered with
 * server-side errors does not shake on first paint.
 *
 * @example
 * <FieldRoot><FieldLabel>Email</FieldLabel><FieldControl /></FieldRoot>
 */
export function FieldRoot({
  className,
  orientation = "vertical",
  shakeSignal,
  onAnimationEnd,
  ref,
  ...props
}: FieldRootProps) {
  // Destructured so hook fields (stable across renders) can appear in dependency arrays
  // without dragging the per-render container object in (react-hooks/exhaustive-deps).
  const {
    invalidRef: shakeInvalidRef,
    className: shakeClassName,
    onAnimationEnd: shakeAnimationEnd,
  } = useShakeOnInvalid({ shakeSignal });
  const rootRef = React.useMemo(
    () => mergeRefs(ref, shakeInvalidRef),
    [ref, shakeInvalidRef],
  );
  const handleAnimationEnd: NonNullable<FieldRootProps["onAnimationEnd"]> =
    React.useCallback(
      (event) => {
        shakeAnimationEnd(event);
        onAnimationEnd?.(event);
      },
      [onAnimationEnd, shakeAnimationEnd],
    );

  return (
    <BaseField.Root
      ref={rootRef}
      data-slot="field"
      data-orientation={orientation}
      className={cn(fieldVariants({ orientation }), shakeClassName, className)}
      onAnimationEnd={handleAnimationEnd}
      {...props}
    />
  );
}

/** Props accepted by `FieldLabel`. */
export type FieldLabelProps = React.ComponentProps<typeof BaseField.Label>;

/**
 * `FieldLabel` — accessible label, auto-associated with the field control.
 * Renders a `<label>`. Uses the `text-label-sm` token (12/500) in `foreground`,
 * non-selectable; dims when the field group is disabled.
 *
 * @example
 * <FieldLabel>Email</FieldLabel>
 */
export function FieldLabel({ className, ref, ...props }: FieldLabelProps) {
  return (
    <BaseField.Label
      ref={ref}
      data-slot="field-label"
      className={cn(
        "flex items-center gap-2 text-label-sm text-foreground select-none",
        "group-has-disabled/field:opacity-(--opacity-dim)",
        className,
      )}
      {...props}
    />
  );
}

/** Props accepted by `FieldControl`. */
export type FieldControlProps = React.ComponentProps<typeof BaseField.Control>;

/**
 * `FieldControl` — the form control to label and validate. Renders the
 * {@link Input} component (the single source of field styling) composed into the
 * Base UI field context, so `id` / `aria-describedby` / `aria-invalid` are wired
 * automatically. Pass `render` to swap in another control, or skip `FieldControl`
 * and drop a sibling control (`<Input>`, `<Checkbox>`, `<Select>`, …) into the field.
 *
 * @example
 * <FieldControl type="email" autoComplete="email" />
 */
export function FieldControl({ ref, ...props }: FieldControlProps) {
  return (
    <BaseField.Control
      ref={ref}
      render={<Input data-slot="field-control" />}
      {...props}
    />
  );
}

/** Props accepted by `FieldDescription`. */
export type FieldDescriptionProps = React.ComponentProps<
  typeof BaseField.Description
>;

/**
 * `FieldDescription` — supporting helper text. Renders a `<p>`, linked to the
 * control via `aria-describedby`. Links use the information color and underline.
 *
 * @example
 * <FieldDescription>Use your work address.</FieldDescription>
 */
export function FieldDescription({
  className,
  ref,
  ...props
}: FieldDescriptionProps) {
  return (
    <BaseField.Description
      ref={ref}
      data-slot="field-description"
      className={cn(
        "text-sm leading-normal text-muted-foreground",
        "[&_a]:text-info-text [&_a]:underline [&_a]:underline-offset-4",
        className,
      )}
      {...props}
    />
  );
}

/** Props accepted by `FieldError`. */
export type FieldErrorProps = React.ComponentProps<typeof BaseField.Error>;

/**
 * `FieldError` — validation error message. Renders a `<div role="status">` only
 * when the control is invalid (or `match` says so). Tinted destructive, and rendered BELOW the
 * control it describes (audit D4).
 *
 * The role is `status`, not `alert` (audit D23): inline field validation is a polite,
 * user-initiated result — the person just typed or submitted and is looking at the field — and
 * `alert` interrupts whatever the screen reader was saying to announce it. `alert` stays
 * reserved for something that arrives without being asked for. `aria-live`/`aria-atomic` are
 * spelled out alongside the role because this element MOUNTS with its text already in it, and a
 * live region inserted complete is announced far less reliably than one whose contents change.
 *
 * The message itself stays still, including when the page first renders invalid — the motion
 * cue is the field's own shake, which `FieldRoot` owns and which fires only on a live
 * valid→invalid transition.
 *
 * @example
 * <FieldError match>Email is required.</FieldError>
 */
export function FieldError({ className, ref, ...props }: FieldErrorProps) {
  return (
    <BaseField.Error
      ref={ref}
      // Base UI's Field.Error has no role; announce the message to assistive tech.
      role="status"
      aria-live="polite"
      aria-atomic="true"
      data-slot="field-error"
      className={cn("text-sm leading-normal text-destructive-text", className)}
      {...props}
    />
  );
}

/** Props accepted by `FieldSuccess`. */
export type FieldSuccessProps = React.ComponentProps<"p">;

/**
 * `FieldSuccess` — positive confirmation message (Base UI Field has no success
 * part, so this is a plain token-styled `<p>`). Tinted success and announced as
 * a polite, atomic status update.
 *
 * @example
 * <FieldSuccess>Address verified.</FieldSuccess>
 */
export function FieldSuccess({ className, ref, ...props }: FieldSuccessProps) {
  return (
    <p
      ref={ref}
      role="status"
      aria-live="polite"
      aria-atomic="true"
      data-slot="field-success"
      className={cn("text-sm leading-normal text-success-text", className)}
      {...props}
    />
  );
}

/** Props accepted by `FieldGroup`. */
export type FieldGroupProps = React.ComponentProps<"div">;

/**
 * `FieldGroup` — stacks a set of fields with consistent rhythm and provides the
 * `@container` that `orientation="responsive"` fields respond to (shadcn Field
 * anatomy).
 *
 * @example
 * <FieldGroup><Field label="Name"><Input /></Field></FieldGroup>
 */
export function FieldGroup({ className, ...props }: FieldGroupProps) {
  return (
    <div
      data-slot="field-group"
      className={cn(
        "@container/field-group flex w-full flex-col gap-6",
        className,
      )}
      {...props}
    />
  );
}

/** Props accepted by `FieldSet`. */
export type FieldSetProps = React.ComponentProps<"fieldset">;

/**
 * `FieldSet` — a semantic `<fieldset>` grouping related fields under a
 * {@link FieldLegend}; dims as a unit when disabled.
 *
 * @example
 * <FieldSet><FieldLegend>Contact details</FieldLegend>{fields}</FieldSet>
 */
export function FieldSet({ className, ...props }: FieldSetProps) {
  return (
    <fieldset
      data-slot="field-set"
      className={cn(
        "flex flex-col gap-4 disabled:opacity-(--opacity-dim)",
        className,
      )}
      {...props}
    />
  );
}

/** Props accepted by `FieldLegend`. */
export type FieldLegendProps = React.ComponentProps<"legend">;

/**
 * `FieldLegend` — the `<legend>` for a {@link FieldSet}, set in the label style.
 *
 * @example
 * <FieldLegend>Contact details</FieldLegend>
 */
export function FieldLegend({ className, ...props }: FieldLegendProps) {
  return (
    <legend
      data-slot="field-legend"
      className={cn("mb-1.5 text-label text-foreground", className)}
      {...props}
    />
  );
}

/** Props accepted by `FieldContent`. */
export type FieldContentProps = React.ComponentProps<"div">;

/**
 * `FieldContent` — groups a label + description column beside a control in
 * horizontal/responsive fields (shadcn Field anatomy).
 *
 * @example
 * <FieldContent><FieldLabel>Email</FieldLabel><FieldDescription>Work address</FieldDescription></FieldContent>
 */
export function FieldContent({ className, ...props }: FieldContentProps) {
  return (
    <div
      data-slot="field-content"
      className={cn("flex min-w-0 flex-1 flex-col gap-1", className)}
      {...props}
    />
  );
}

/* ------------------------------------------------------------------------------------------------
 * Prop-driven Field — the ergonomic default. Composes the primitives from
 * `label` / `description` / `error` / `success` props around a single control.
 * ----------------------------------------------------------------------------------------------*/

/** Props accepted by `Field`. */
export interface FieldProps extends FieldRootProps {
  /**
   * The field label, rendered above (vertical) or beside (horizontal) the
   * control and auto-associated with it for accessibility.

   * @default undefined
   */
  label?: React.ReactNode;
  /**
   * Inline action rendered on the same row as the label, end-aligned — e.g. a
   * "Forgot password?" link. Vertical orientation only.

   * @default undefined
   */
  labelAction?: React.ReactNode;
  /**
   * Helper text rendered BELOW the control, above any error or success message, and linked to
   * the control via `aria-describedby` (audit D4). In `orientation="responsive"` it stays in the
   * label column, which is the whole point of that layout.

   * @default undefined
   */
  description?: React.ReactNode;
  /**
   * Error message. When set (and `invalid` is not explicitly `false`), the field
   * is treated as invalid: the message shows in destructive color and the
   * control receives `aria-invalid`.

   * @default undefined
   */
  error?: React.ReactNode;
  /**
   * Positive confirmation message, rendered in success color below the control.
   * Ignored while `error` is present.

   * @default undefined
   */
  success?: React.ReactNode;
  /**
   * Strip the border, background, and shadow from the child control — for inline
   * editing (titles, descriptions). The control keeps its focus border tint.
   * @default false
   */
  borderless?: boolean;
  /** The field control(s) — an `<Input>`, `<Checkbox>`, `FieldControl`, etc. */
  children: React.ReactNode;
}

/** Child-control styling hooks, keyed by the control's own `data-slot`. */
const CONTROL_SLOTS =
  "[&_[data-slot=field-control]]:text-base [&_[data-slot=input]]:text-base";

/**
 * Borderless overrides — flatten inputs/textareas/select-triggers for inline edit.
 *
 * The transparent border is scoped to `:not(:focus)` (#100, 2026-09-09). `borderless` documents
 * that "the control keeps its focus border tint", and it did not: these descendant selectors and
 * `fieldControl`'s `focus:border-ring/(--alpha-tint-border)` are the same property at the same
 * specificity, and Tailwind v4 emits an arbitrary variant AFTER a plain one, so `border-transparent`
 * won in every state. A text-entry control carries `outline-hidden`, so a borderless field had no
 * focus affordance at all. Standing the override down on focus restores the documented behaviour
 * without giving the flattened control a resting border.
 *
 * It is scoped past the INVALID state for the same reason (2026-09-09). `border-transparent`
 * outranked `fieldControl`'s invalid tint identically, so a borderless field that failed validation
 * measured a resting `border-color: rgba(0, 0, 0, 0)` — error copy and the shake fired, but the
 * control itself carried no resting cue at all, which is the one state where a flattened field most
 * needs one. Both attribute forms are excluded because the two halves of the recipe are spelled
 * differently: `aria-invalid` on the native control, Base UI's `data-invalid` on a Select trigger.
 *
 * `.join(" ")`, not `+` — see `design-lint`'s `class-glue` rule.
 */
const BORDERLESS = [
  "[&_[data-slot=field-control]:not(:focus):not([aria-invalid='true']):not([data-invalid])]:border-transparent [&_[data-slot=field-control]]:bg-transparent [&_[data-slot=field-control]]:px-0 [&_[data-slot=field-control]]:shadow-none",
  "[&_[data-slot=input]:not(:focus):not([aria-invalid='true']):not([data-invalid])]:border-transparent [&_[data-slot=input]]:bg-transparent [&_[data-slot=input]]:px-0 [&_[data-slot=input]]:shadow-none",
  "[&_[data-slot=textarea]:not(:focus):not([aria-invalid='true']):not([data-invalid])]:border-transparent [&_[data-slot=textarea]]:bg-transparent [&_[data-slot=textarea]]:px-0 [&_[data-slot=textarea]]:shadow-none",
  "[&_[data-slot=select-trigger]:not(:focus):not([aria-invalid='true']):not([data-invalid])]:border-transparent [&_[data-slot=select-trigger]]:bg-transparent [&_[data-slot=select-trigger]]:px-0 [&_[data-slot=select-trigger]]:shadow-none",
].join(" ");

/**
 * `Field` — the ergonomic, prop-driven form-field wrapper. Composes a Base UI
 * `Field.Root` with a label (+ optional inline `labelAction`), `description`,
 * and `error`/`success` message around a single control passed as `children`.
 * Base UI auto-wires `aria-describedby`/`aria-invalid` between the parts.
 *
 * For full control over composition, use the exported primitives directly:
 * `FieldRoot`, `FieldLabel`, `FieldControl`, `FieldDescription`, `FieldError`.
 *
 * @example
 * // Vertical (default) — label above input
 * <Field label="Email" description="We'll never share it.">
 *   <Input type="email" placeholder="you@vegastack.com" />
 * </Field>
 *
 * @example
 * // With an inline label action + error
 * <Field label="Password" labelAction={<a href="/forgot">Forgot?</a>} error="Required">
 *   <Input type="password" />
 * </Field>
 *
 * @example
 * // Horizontal — control beside label (checkboxes, switches)
 * <Field label="Set as default" orientation="horizontal">
 *   <Checkbox />
 * </Field>
 */
export function Field({
  className,
  orientation = "vertical",
  label,
  labelAction,
  description,
  error,
  success,
  borderless = false,
  invalid,
  children,
  ...props
}: FieldProps) {
  const isHorizontal = orientation === "horizontal";
  const isResponsive = orientation === "responsive";
  const isInvalid = invalid ?? Boolean(error);
  const hasHeader = label != null || labelAction != null;

  return (
    <FieldRoot
      orientation={orientation}
      invalid={isInvalid}
      className={cn(CONTROL_SLOTS, borderless && BORDERLESS, className)}
      {...props}
    >
      {isResponsive ? (
        <>
          {/* Responsive: label+description form a FieldContent column that sits left of the
              control from the wrapping FieldGroup's @md width, stacked below it. */}
          <FieldContent>
            {label != null ? <FieldLabel>{label}</FieldLabel> : null}
            {description != null ? (
              <FieldDescription>{description}</FieldDescription>
            ) : null}
          </FieldContent>
          {children}
        </>
      ) : isHorizontal ? (
        <>
          {children}
          {label != null ? (
            <FieldLabel className="cursor-pointer">{label}</FieldLabel>
          ) : null}
          {/* Description wraps to its own full-width line under the control+label row,
              mirroring FieldError's horizontal treatment (register P0-05). */}
          {description != null ? (
            <FieldDescription className="basis-full">
              {description}
            </FieldDescription>
          ) : null}
        </>
      ) : (
        <>
          {hasHeader ? (
            <div
              data-slot="field-header"
              className="flex items-baseline justify-between gap-2"
            >
              {label != null ? <FieldLabel>{label}</FieldLabel> : <span />}
              {labelAction != null ? (
                <span
                  data-slot="field-label-action"
                  className="text-label-sm text-muted-foreground [&_a]:text-info-text [&_a]:underline [&_a]:underline-offset-4"
                >
                  {labelAction}
                </span>
              ) : null}
            </div>
          ) : null}
          {children}
          {/* Helper text sits UNDER the control (audit D4/B1-07). Above it, the description
              pushed the input away from its own label and, when it wrapped, put two lines of
              prose between the two things the eye pairs. Geist, Linear, Raycast, Apple HIG and
              Material all place it here, and the error/success message extends the same line. */}
          {description != null ? (
            <FieldDescription>{description}</FieldDescription>
          ) : null}
        </>
      )}
      {error != null ? (
        <FieldError
          match={isInvalid}
          className={cn(isHorizontal && "basis-full")}
        >
          {error}
        </FieldError>
      ) : success != null ? (
        <FieldSuccess className={cn(isHorizontal && "basis-full")}>
          {success}
        </FieldSuccess>
      ) : null}
    </FieldRoot>
  );
}

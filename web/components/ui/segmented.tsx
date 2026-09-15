"use client";

import * as React from "react";
import { ToggleGroup as BaseToggleGroup } from "@base-ui/react/toggle-group";
import { Toggle as BaseToggle } from "@base-ui/react/toggle";
import { cva, type VariantProps } from "class-variance-authority";
import { cn, selectedChipVariants } from "@vegastack/design";

/* ------------------------------------------------------------------------------------------------
 * Segmented — the canonical segmented control (Wave 2, promoted from the ToggleGroup recipe after
 * the Attio teardown found the identical formula on marketing AND app surfaces): a muted track with
 * a raised active chip. Radio semantics — exactly one segment is always selected; a click on the
 * active segment is a no-op (unlike ToggleGroup, which allows an empty selection). Built on Base UI
 * ToggleGroup/Toggle so keyboard arrows, focus management, and `aria-pressed` come from the
 * primitive. The nested-radius formula: track `rounded-md` + `p-0.5` → chip `rounded-sm`.
 *
 * @example
 * <Segmented defaultValue="monthly" aria-label="Billing cycle">
 *   <SegmentedItem value="monthly">Monthly</SegmentedItem>
 *   <SegmentedItem value="annual">Annual</SegmentedItem>
 * </Segmented>
 * ----------------------------------------------------------------------------------------------*/

const SegmentedContext = React.createContext<{ size: "md" | "lg" }>({
  size: "md",
});

export const segmentedVariants = cva(
  cn(
    "inline-flex w-fit items-center gap-0.5 rounded-md p-0.5 text-muted-foreground",
    selectedChipVariants.track,
  ),
  {
    variants: {
      size: {
        /** 28px track (24px chips) — the dense chrome scale. */
        md: "",
        /** 32px track (28px chips) — form-row scale. */
        lg: "",
      },
    },
    defaultVariants: { size: "md" },
  },
);

export const segmentedItemVariants = cva(
  cn(
    "inline-flex min-w-0 shrink-0 items-center justify-center gap-1.5 rounded-sm text-label-sm whitespace-nowrap select-none",
    // The look — rest, hover, pressed AND selected — is the shared recipe, so a Segmented chip and
    // a pill/chip tab cannot drift apart again (B6-02). It also keeps the SELECTED chip stepping:
    // before this, `not-data-pressed:` excluded the selected chip from hover and press entirely, so
    // the one chip a user is most likely to click was the one that answered nothing (the probe's
    // `active-same-as-hover`).
    selectedChipVariants.item,
    selectedChipVariants.pressed,
    "disabled:pointer-events-none disabled:opacity-(--opacity-dim)",
    "[&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-(--icon-compact)",
  ),
  {
    variants: {
      size: {
        md: "h-(--size-xs) px-2.5",
        lg: "h-(--size-sm) px-3 text-label [&_svg:not([class*='size-'])]:size-(--icon-inline)",
      },
    },
    defaultVariants: { size: "md" },
  },
);

/** Props for the single-select {@link Segmented} track. */
export interface SegmentedProps
  extends
    Omit<
      React.ComponentProps<typeof BaseToggleGroup>,
      "value" | "defaultValue" | "multiple" | "onValueChange"
    >,
    VariantProps<typeof segmentedVariants> {
  /**
   * The selected segment's `value`. Controlled counterpart of `defaultValue`.
   * @default undefined
   */
  value?: string;
  /**
   * The initially selected segment's `value`. Defaults to the first enabled direct item.
   * @default first enabled item
   */
  defaultValue?: string;
  /**
   * Fired with the newly selected segment `value`. Never fires with "nothing selected".
   * @default undefined
   */
  onValueChange?: (value: string) => void;
  /**
   * Track density — `md` (24px chips in a 28px track, chrome scale) or
   * `lg` (28px chips, form-row scale).
   * @default 'md'
   */
  size?: "md" | "lg";
}

/**
 * `Segmented` — a segmented control: single-select, always-one-selected view/mode
 * switcher on a muted track. Use it where the options are peers and one is always
 * active (view modes, billing cycles, filter scopes); use `Tabs` when panels of
 * content swap, and `ToggleGroup` when empty/multiple selection is meaningful.
 *
 * @example
 * <Segmented defaultValue="grid" aria-label="View">
 *   <SegmentedItem value="grid">Grid</SegmentedItem>
 *   <SegmentedItem value="list">List</SegmentedItem>
 * </Segmented>
 */
export function Segmented({
  className,
  size = "md",
  value,
  defaultValue,
  onValueChange,
  children,
  ref,
  ...props
}: SegmentedProps) {
  const contextValue = React.useMemo(() => ({ size }), [size]);
  const firstEnabledValue = React.Children.toArray(children).find(
    (
      child,
    ): child is React.ReactElement<{ disabled?: boolean; value?: unknown }> =>
      React.isValidElement<{ disabled?: boolean; value?: unknown }>(child) &&
      typeof child.props.value === "string" &&
      !child.props.disabled,
  )?.props.value as string | undefined;
  // Radio semantics over the primitive's array model: the group is ALWAYS
  // controlled internally, so the empty selection Base UI produces when the
  // active segment is clicked again can never land — uncontrolled usage keeps
  // its selection, and the public callback only ever fires with a value.
  const [internalValue, setInternalValue] = React.useState(
    () => defaultValue ?? firstEnabledValue,
  );
  const selected = value ?? internalValue ?? firstEnabledValue;
  const handleValueChange = React.useCallback(
    (groupValue: string[]) => {
      const next = groupValue[0];
      if (next == null) return; // re-click on the active segment — no-op
      if (value == null) setInternalValue(next);
      onValueChange?.(next);
    },
    [onValueChange, value],
  );
  const rootClassName = segmentedVariants({ size });
  const resolvedClassName: React.ComponentProps<
    typeof BaseToggleGroup
  >["className"] =
    typeof className === "function"
      ? (state) => cn(rootClassName, className(state))
      : cn(rootClassName, className);

  return (
    <BaseToggleGroup
      ref={ref}
      data-slot="segmented"
      data-size={size}
      multiple={false}
      value={selected != null ? [selected] : []}
      onValueChange={handleValueChange}
      className={resolvedClassName}
      {...props}
    >
      <SegmentedContext.Provider value={contextValue}>
        {children}
      </SegmentedContext.Provider>
    </BaseToggleGroup>
  );
}

/** Props for one selectable {@link SegmentedItem} chip. */
export interface SegmentedItemProps
  extends
    React.ComponentProps<typeof BaseToggle>,
    VariantProps<typeof segmentedItemVariants> {
  /**
   * Density override for a single chip.
   * @default inherited from Segmented
   */
  size?: "md" | "lg";
}

/**
 * `SegmentedItem` — one chip in a `Segmented` control. Identify it with `value`;
 * the selected chip raises on the shared `selectedChipVariants` recipe — the
 * pressed/selected rung with the one hairline border
 * (`data-pressed`). Compose a leading icon as the first child.
 *
 * @example
 * <SegmentedItem value="monthly">Monthly</SegmentedItem>
 */
export function SegmentedItem({
  className,
  size,
  children,
  ref,
  ...props
}: SegmentedItemProps) {
  const context = React.useContext(SegmentedContext);
  const resolvedSize = size ?? context.size ?? "md";
  const variantClassName = segmentedItemVariants({ size: resolvedSize });
  const resolvedClassName: React.ComponentProps<
    typeof BaseToggle
  >["className"] =
    typeof className === "function"
      ? (state) => cn(variantClassName, className(state))
      : cn(variantClassName, className);

  return (
    <BaseToggle
      ref={ref}
      data-slot="segmented-item"
      data-size={resolvedSize}
      className={resolvedClassName}
      {...props}
    >
      {children}
    </BaseToggle>
  );
}

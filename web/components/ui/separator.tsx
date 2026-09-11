"use client";

import * as React from "react";
import { Separator as BaseSeparator } from "@base-ui/react/separator";
import { cn } from "@vegastack/design";

/** Props accepted by `Separator`. */
export interface SeparatorProps extends React.ComponentProps<
  typeof BaseSeparator
> {
  /**
   * Axis the separator divides along. `horizontal` renders a 1px-tall full-width
   * rule; `vertical` renders a 1px-wide full-height rule.
   * @default 'horizontal'
   */
  orientation?: "horizontal" | "vertical";
  /**
   * Whether the separator is purely visual. When `true` (the default) it is
   * hidden from assistive tech (`role="presentation"`, `aria-hidden`) since the
   * surrounding layout already conveys the grouping. Set to `false` when the
   * divider carries semantic meaning (e.g. separating menu sections) so screen
   * readers announce it as a `separator`.
   * @default true
   */
  decorative?: boolean;
}

/**
 * `Separator` — a thin rule that visually or semantically divides content.
 * Built on Base UI's accessible `Separator`. Horizontal by default; pass
 * `orientation="vertical"` inside a flex row (the parent must give it height).
 * Decorative by default — set `decorative={false}` to expose it to assistive
 * technology as a `separator`.
 *
 * @example
 * <Separator decorative={false} />
 */
export function Separator({
  className,
  orientation = "horizontal",
  decorative = true,
  ...props
}: SeparatorProps) {
  // Base UI's Separator always emits role="separator" + aria-orientation. For a
  // decorative rule we override the semantics so assistive tech skips it; for a
  // semantic one we let Base UI manage the ARIA so we don't fight it.
  const decorativeProps = decorative
    ? ({
        role: "presentation",
        "aria-hidden": true,
        "aria-orientation": undefined,
      } as const)
    : {};

  return (
    <BaseSeparator
      data-slot="separator"
      orientation={orientation}
      {...decorativeProps}
      className={cn(
        "shrink-0 bg-border data-[orientation=horizontal]:h-px data-[orientation=horizontal]:w-full data-[orientation=vertical]:h-full data-[orientation=vertical]:w-px",
        className,
      )}
      {...props}
    />
  );
}

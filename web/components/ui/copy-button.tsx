"use client";

import * as React from "react";
import { Check, Copy } from "lucide-react";
import { cn, TIMINGS } from "@vegastack/design";
// `Button` is owned by the sibling Button component; shadcn rewrites this alias on
// `add`, and vitest/tsconfig map `@/components/ui/*` → `registry/ui/*`.
import {
  Button,
  type ButtonAppearance,
  type ButtonOwnProps,
} from "@/components/ui/button";
import { IconButton, type IconButtonProps } from "@/components/ui/icon-button";
import { useAnnouncer } from "@/components/ui/use-announcer";

/** Props accepted by `CopyButton`. */
export type CopyButtonProps = Omit<
  ButtonOwnProps,
  "aria-label" | "children" | "onClick" | "type" | "value"
> &
  ButtonAppearance & {
    /**
     * The text written to the clipboard when the button is pressed.
     */
    value: string;
    /**
   * Fired after `value` is successfully copied to the clipboard. Use it to show a
   * toast or analytics event — the transient check feedback is handled internally.

   * @default undefined
   */
    onCopied?: (value: string) => void;
    /**
     * How long (in milliseconds) the check icon stays visible before reverting to
     * the copy icon.
     * @default 1500
     */
    timeout?: number;
    /**
     * Accessible label before the value has been copied.
     * @default 'Copy'
     */
    copyLabel?: string;
    /**
     * Accessible label while the copied confirmation is visible.
     * @default 'Copied'
     */
    copiedLabel?: string;
    /**
     * Show the current copy status as visible text beside the icon. With a label the control is a
     * text `Button`; without one it is an `IconButton`. An explicit `size` still wins.
     * @default false
     */
    showLabel?: boolean;
    /**
   * Called when the copy button is pressed before the clipboard write runs.
   * Calling `event.preventDefault()` cancels the write.

   * @default undefined
   */
    onPress?: (event: React.MouseEvent<HTMLElement>) => void;
  };

/**
 * `CopyButton` — copy a string to the clipboard with transient check feedback.
 *
 * Wraps `IconButton` (default `ghost` / `sm`), or `Button` when `showLabel` is set, and swaps the
 * `lucide-react`
 * `Copy` icon for a `Check` for ~1.5s after a successful copy, tinting it
 * `text-primary` for that window. Copying is neutral action feedback rather than a
 * semantic success status. The accessible label switches from `"Copy"` to
 * `"Copied"` so screen readers announce the result; the icon itself is decorative
 * (`aria-hidden`). The confirmation is spoken by the shared `useAnnouncer` live region —
 * `aria-label` changes on the button itself are not reliably announced by screen readers.
 * Client-only — it uses `useState` + `navigator.clipboard`.
 *
 * @example
 * <CopyButton value={apiKey} onCopied={() => toast.success('Copied')} />
 */
export function CopyButton({
  value,
  onCopied,
  timeout = TIMINGS.feedbackRevertMs,
  copyLabel = "Copy",
  copiedLabel = "Copied",
  showLabel = false,
  variant = "ghost",
  tone,
  size,
  className,
  onPress,
  ...props
}: CopyButtonProps) {
  const [copied, setCopied] = React.useState(false);
  const { announce, Announcer } = useAnnouncer();
  const timer = React.useRef<ReturnType<typeof setTimeout> | undefined>(
    undefined,
  );

  // Clear any pending reset on unmount so we never set state on a gone component.
  React.useEffect(() => () => clearTimeout(timer.current), []);

  const handleClick = React.useCallback(
    async (event: React.MouseEvent<HTMLElement>) => {
      onPress?.(event);
      if (event.defaultPrevented) return;
      try {
        await navigator.clipboard.writeText(value);
        setCopied(true);
        announce(copiedLabel);
        onCopied?.(value);
        clearTimeout(timer.current);
        timer.current = setTimeout(() => setCopied(false), timeout);
      } catch {
        // Clipboard write can reject (denied permission, insecure context) —
        // leave the button in its default state rather than show a false success.
      }
    },
    [announce, copiedLabel, onCopied, onPress, timeout, value],
  );

  // A label-less CopyButton is icon-only, so it goes through `IconButton` — the ONE sanctioned
  // icon-only path, and the reason the `aria-label` below can never go missing. With a visible
  // label it is a normal text Button.
  // One JSX tree, two hosts: the cast is safe because `aria-label` (IconButton's only extra
  // requirement) is always supplied below.
  const Control = (
    showLabel ? Button : IconButton
  ) as React.ComponentType<IconButtonProps>;
  // Assembled once and cast once: `variant`/`tone` are a discriminated pair on the Button matrix,
  // and spreading them across separate JSX attributes loses that pairing.
  const controlProps = {
    ...props,
    type: "button",
    variant,
    tone,
    size: size ?? "sm",
    "data-slot": "copy-button",
    "data-copied": copied ? "" : undefined,
    "data-label-visible": showLabel ? "" : undefined,
    "aria-label": copied ? copiedLabel : copyLabel,
    onClick: handleClick,
    className: cn(copied && "text-primary hover:text-primary", className),
  } as unknown as IconButtonProps;

  return (
    <Control {...controlProps}>
      {/*
       * Keyed presence (CX-13): the key ties each icon to the copied boundary so
       * it remounts and its pop-in mount animation replays on every swap. A
       * stroke-draw treatment was the intended arrival for the success check, but
       * it's not reachable here: lucide-react's icon factory spreads consumer
       * props only onto the root svg element — the generated path is built
       * straight from the icon's fixed node array with no prop merge — so a
       * path-length attribute can never land on the path itself through the
       * public Check component's API. A hand-rolled svg reproducing the check
       * glyph would work around that, but it's barred by the icon house rule
       * (only lucide-react via the sanctioned wrappers; no hand-authored icon
       * markup). Both icons fall back to the pop-in utility instead (documented
       * deviation — see docs/plans/.m-swap-summary.md).
       */}
      {copied ? (
        <Check key="check" aria-hidden className="motion-pop-in" />
      ) : (
        <Copy key="copy" aria-hidden className="motion-pop-in" />
      )}
      {showLabel ? (
        <span data-slot="copy-button-label">
          {copied ? copiedLabel : copyLabel}
        </span>
      ) : null}
      {/* The live region IS the announcement mechanism — the button's `aria-label` swap
          alone is not reliably announced. `use-announcer` mounts it empty from first paint
          (a region inserted at the moment it gains content is frequently missed) and
          re-keys it per call, so copying twice in a row speaks twice. */}
      <Announcer />
    </Control>
  );
}

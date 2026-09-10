"use client";

import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { Button as BaseButton } from "@base-ui/react/button";
import { Spinner } from "@/components/ui/spinner";
import { cn } from "@vegastack/design";

/**
 * Button variants — base, semantic-filled, semantic-outline, and glass.
 * Every value is a semantic token (no hardcoded colors).
 */
export const buttonVariants = cva(
  // `text-label` is the chrome-control voice (14/500, −1% tracking) — the same voice every
  // other control label uses, so buttons don't read fractionally looser than tabs/segments/
  // menu items sitting beside them. Size variants below layer `text-sm`, which overrides only
  // font-size + line-height; the weight and tracking from `text-label` persist, so the small
  // tiers land on the `text-label-sm` metrics (12/500, −1%) without restating them.
  "inline-flex shrink-0 items-center justify-center gap-1.5 rounded-md border border-transparent bg-clip-padding text-label whitespace-nowrap select-none disabled:pointer-events-none disabled:opacity-(--opacity-dim) aria-invalid:border-destructive-border/(--alpha-tint-border) [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-(--icon-default)",
  {
    variants: {
      variant: {
        default:
          "bg-primary text-primary-foreground hover:bg-primary-hover active:bg-primary-active",
        secondary:
          "bg-secondary text-secondary-foreground hover:bg-secondary/(--alpha-fill-hover)",
        outline:
          "border-border bg-background hover:bg-muted hover:text-foreground focus-visible:border-ring/(--alpha-tint-border) dark:border-input dark:bg-input/(--alpha-input) dark:hover:bg-input/(--alpha-input-hover)",
        ghost:
          "hover:bg-muted hover:text-foreground dark:hover:bg-muted/(--alpha-wash)",
        link: "text-info-text underline underline-offset-4 hover:text-info-text/(--alpha-link-hover)",
        destructive:
          "bg-destructive-subtle text-destructive-text hover:bg-destructive-subtle-hover",
        success:
          "bg-success-subtle text-success-text hover:bg-success-subtle-hover",
        warning:
          "bg-warning-subtle text-warning-text hover:bg-warning-subtle-hover",
        info: "bg-info-subtle text-info-text hover:bg-info-subtle-hover",
        glass:
          "border-border bg-background/(--alpha-glass) text-foreground backdrop-blur-glass hover:bg-background/(--alpha-glass-hover)",
        "destructive-outline":
          "border-destructive/(--alpha-outline-border) bg-destructive/(--alpha-surface-faint) text-destructive-text hover:border-destructive hover:bg-destructive/(--alpha-surface-subtle)",
        "success-outline":
          "border-success/(--alpha-outline-border) bg-success/(--alpha-surface-faint) text-success-text hover:border-success hover:bg-success/(--alpha-surface-subtle)",
        "warning-outline":
          "border-warning/(--alpha-outline-border) bg-warning/(--alpha-surface-faint) text-warning-text hover:border-warning hover:bg-warning/(--alpha-surface-subtle)",
        "info-outline":
          "border-info/(--alpha-outline-border) bg-info/(--alpha-surface-faint) text-info-text hover:border-info hover:bg-info/(--alpha-surface-subtle)",
        // Marketing CTA (audit 17-brand-direction §Color & surface + §Shape): the ONE sanctioned
        // use of the `--brand` phosphor accent as a button — accent-outline, sharp corners
        // (rounded-(--radius-sharp), rationed per D18), mono-uppercase label (the brand voice
        // layer). `rounded-(--radius-sharp)` / `text-mono-label` win over the base string's
        // `rounded-md` / `text-label` via later-in-source-order cascade — the SAME mechanism the
        // `outline` variant above already relies on (`border-border` overriding the base's
        // `border-transparent`). Compose a trailing chevron as a CHILD (e.g. `<ChevronRight />`)
        // — this variant is style-only, it never bakes in an icon.
        cta: "rounded-(--radius-sharp) border-brand/(--alpha-outline-border) bg-brand/(--alpha-surface-faint) font-mono text-mono-label text-brand uppercase hover:border-brand hover:bg-brand/(--alpha-surface-subtle) active:bg-brand/(--alpha-surface-subtle)",
      },
      size: {
        // Text-bearing sizes pair their composed icon with the TEXT — `--icon-inline` (14px,
        // matching the 14px label) — while the icon-only squares below keep the standalone
        // `--icon-default` (16px) from the base class. A 16px stroke-2 lucide glyph next to a
        // 14px label reads disproportionately heavy (MK sweep finding); xs/sm already followed
        // this proportional ladder, default/lg were the gap.
        default:
          "h-(--size-md) gap-1.5 px-3 [&_svg:not([class*='size-'])]:size-(--icon-inline)",
        xs: "h-(--size-xs) gap-1 px-2 text-label-sm [&_svg:not([class*='size-'])]:size-(--icon-compact)",
        sm: "h-(--size-sm) gap-1 px-2.5 text-label-sm [&_svg:not([class*='size-'])]:size-(--icon-inline)",
        lg: "h-(--size-lg) gap-1.5 px-4 [&_svg:not([class*='size-'])]:size-(--icon-inline)",
        icon: "size-(--size-md)",
        "icon-xs":
          "size-(--size-xs) [&_svg:not([class*='size-'])]:size-(--icon-compact)",
        "icon-sm":
          "size-(--size-sm) [&_svg:not([class*='size-'])]:size-(--icon-inline)",
        "icon-lg": "size-(--size-lg)",
      },
      /**
       * Material finish (Wave 2, MK-approved flat-by-default amendment):
       * `flat` (default) keeps the system's flat elevation model; `lit` adds the
       * `--shadow-lit` top-light + warm ambient pair — PRIMARY actions only, so
       * it is expressed as compound variants on the solid `default` fill (and
       * deliberately nothing else: soft/outline/ghost/link surfaces stay flat).
       */
      finish: {
        flat: "",
        lit: "",
      },
    },
    compoundVariants: [
      { finish: "lit", variant: "default", class: "shadow-(--shadow-lit)" },
    ],
    defaultVariants: { variant: "default", size: "default", finish: "flat" },
  },
);

type BaseButtonProps = React.ComponentPropsWithRef<typeof BaseButton>;

/** Props accepted by `Button`. */
export interface ButtonProps
  extends
    Omit<BaseButtonProps, "className">,
    VariantProps<typeof buttonVariants> {
  /** Classes or a Base UI state resolver merged with the button variants.
   * @default undefined
   */
  className?: BaseButtonProps["className"];
  /**
   * Slot marker for wrapper components that compose Button through Base UI
   * `render` and need their own generated registry slot.
   * @default 'button'
   */
  "data-slot"?: string;
  /**
   * Loading-state marker for wrapper components that reflect a host-owned pending
   * state onto a composed Button without its `loading` visuals (e.g. SplitButton's
   * chevron half). The Button's own `loading` prop always wins when set.

   * @default undefined
   */
  "data-loading"?: string;
  /**
   * Shows a spinner, disables interaction, and sets `aria-busy`.
   * @default false
   */
  loading?: boolean;
  /**
   * Material finish. `lit` adds the `--shadow-lit` top-light + ambient pair —
   * applied only when it composes with the solid `default` variant (the
   * primary action); every other variant stays flat by design.
   * @default 'flat'
   */
  finish?: "flat" | "lit";
}

/**
 * `Button` — trigger an action. Built on Base UI Button, so `render`,
 * `nativeButton`, and `focusableWhenDisabled` follow the official primitive
 * contract. Use for primary/secondary/destructive actions, not URL navigation
 * (style an anchor with `buttonVariants` when the action is a link).
 *
 * @example
 * <Button type="submit" loading={isSaving}>Save changes</Button>
 */
export function Button({
  className,
  variant = "default",
  size = "default",
  finish = "flat",
  loading = false,
  disabled,
  children,
  type = "button",
  focusableWhenDisabled,
  "aria-busy": ariaBusy,
  "data-slot": dataSlot,
  "data-loading": dataLoading,
  ref,
  ...props
}: ButtonProps) {
  const isDisabled = disabled || loading;
  // Fixed-square icon sizes fit exactly ONE glyph — while loading, the spinner REPLACES the
  // icon child (prepending it would overflow the square: spinner clipped left, icon spilling
  // right). The accessible name is unaffected: icon-only buttons are named via `aria-label`
  // (enforced by `IconButton`), never by the swapped-out icon, and `aria-busy` still announces
  // the pending state. Text sizes keep their children next to the spinner as before.
  const isIconSize = size != null && size.startsWith("icon");
  const variantClassName = buttonVariants({ variant, size, finish });
  const resolvedClassName: BaseButtonProps["className"] =
    typeof className === "function"
      ? (state) => cn(variantClassName, className(state))
      : cn(variantClassName, className);

  return (
    <BaseButton
      {...props}
      ref={ref}
      type={type}
      data-slot={dataSlot ?? "button"}
      data-variant={variant}
      data-size={size}
      data-finish={finish === "lit" ? "lit" : undefined}
      data-loading={loading ? "" : dataLoading}
      aria-busy={loading ? true : ariaBusy}
      disabled={isDisabled}
      focusableWhenDisabled={
        focusableWhenDisabled ?? (loading ? true : undefined)
      }
      className={resolvedClassName}
    >
      {loading ? <Spinner size="inherit" label="" /> : null}
      {loading && isIconSize ? null : children}
    </BaseButton>
  );
}

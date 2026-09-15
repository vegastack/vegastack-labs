import * as React from "react";
import { cn } from "@vegastack/design";
import {
  Button,
  type ButtonAppearance,
  type ButtonOwnProps,
  type ButtonProps,
} from "@/components/ui/button";

/** The four square icon-only sizes — the same `xs · sm · md · lg` vocabulary every control uses. */
export type IconButtonSize = "xs" | "sm" | "md" | "lg";

/** `square` is the default chrome shape; `round` is for avatars, media transports and pills. */
export type IconButtonShape = "square" | "round";

/**
 * Icon-only geometry: pin the width to the height so the control is a perfect square, drop the
 * horizontal padding a text button needs, and give the two larger tiers the standalone 16px glyph
 * (`--icon-default`) rather than the 14px one a text button pairs with its label. `Button` owns the
 * height; these classes are merged after it, so `w-*` / `px-0` win.
 */
const squareBySize: Record<IconButtonSize, string> = {
  xs: "w-(--size-xs) px-0",
  sm: "w-(--size-sm) px-0",
  md: "w-(--size-md) px-0 [&_svg:not([class*='size-'])]:size-(--icon-default)",
  lg: "w-(--size-lg) px-0 [&_svg:not([class*='size-'])]:size-(--icon-default)",
};

/**
 * `iconButtonGeometry` — the square (or round) icon-only geometry as a class string, to pair with
 * `buttonVariants()` on an **anchor**. `Button` and `IconButton` are for actions; navigation is a
 * real `<a>`, styled to match (`design.md` §Components · Button). Rendering an anchor through
 * `IconButton` would force `role="button"` onto a link, which is why this is a helper and not a
 * `render` prop.
 *
 * @example
 * <a href={backHref} aria-label="Go back"
 *    className={cn(buttonVariants({ variant: "ghost", size: "sm" }), iconButtonGeometry("sm"))}>
 *   <ChevronLeft aria-hidden />
 * </a>
 */
export function iconButtonGeometry(
  size: IconButtonSize = "md",
  shape: IconButtonShape = "square",
): string {
  return cn(squareBySize[size], shape === "round" && "rounded-full");
}

/**
 * Props for `IconButton`. Inherits every `Button` prop except `size` (remapped to the square
 * `IconButtonSize` scale) and requires an accessible `aria-label` because the icon child carries
 * no text.
 */
export type IconButtonOwnProps = Omit<ButtonOwnProps, "size" | "aria-label"> & {
  /**
   * The icon to render. Pass a single `lucide-react` (or `@vegastack/design/icons`)
   * element — it is sized automatically by the chosen `size`. Optional only so the control can be
   * composed through Base UI `render`, where the host supplies the children.
   * @default undefined
   */
  children?: React.ReactNode;
  /**
   * Square size, from the one `--size-*` vocabulary.
   * @default 'md'
   */
  size?: IconButtonSize;
  /**
   * Outline shape. `round` is the sanctioned way to get a circular control — a `rounded-full`
   * override on a Button is not.
   * @default 'square'
   */
  shape?: IconButtonShape;
  /**
   * Accessible name announced to assistive tech (required — the icon has no
   * visible text).
   */
  "aria-label": string;
};

/** Props accepted by `IconButton`. */
export type IconButtonProps = IconButtonOwnProps & ButtonAppearance;

/**
 * `IconButton` — a square (or round) icon-only action button. A thin wrapper over `Button` that
 * forces icon-only geometry and **requires** an accessible `aria-label`, since there is no visible
 * text to name it. `variant`, `tone`, `loading`, `disabled`, and `render` pass straight through.
 *
 * **Why this exists (RETAINED by decision — register P1-21 reversed):** the whole job of the
 * wrapper is the **compile-time accessible-name guarantee**. A bare `Button` with a single icon
 * child accepts an unnamed control silently; `IconButton` makes the missing `aria-label` a TYPE
 * ERROR. It is the ONLY sanctioned icon-only path — `Button` has no icon size tier at all, and a
 * hand-rolled `<button>` with an icon in it is a design-lint violation.
 *
 * @example
 * <IconButton aria-label="Add item" variant="outline" size="sm">
 *   <Plus />
 * </IconButton>
 * @example
 * <IconButton aria-label="Dismiss" variant="ghost" size="xs" shape="round" onClick={close}>
 *   <X />
 * </IconButton>
 */
export function IconButton({
  size = "md",
  shape = "square",
  className,
  children,
  "data-slot": dataSlot,
  ...props
}: IconButtonProps) {
  const geometry = iconButtonGeometry(size, shape);
  const resolvedClassName: ButtonProps["className"] =
    typeof className === "function"
      ? (state) => cn(geometry, className(state))
      : cn(geometry, className);

  return (
    <Button
      {...(props as ButtonProps)}
      size={size}
      data-slot={dataSlot ?? "icon-button"}
      data-shape={shape}
      className={resolvedClassName}
    >
      {children}
    </Button>
  );
}

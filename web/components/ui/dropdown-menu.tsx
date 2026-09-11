"use client";

import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { Menu } from "@base-ui/react/menu";
import { CheckIcon, ChevronRightIcon, CircleIcon } from "lucide-react";
import { cn, FLOATING } from "@vegastack/design";
import { useInternalThemeScope } from "@vegastack/design/theme-scope";

function mergeStateClassName<State>(
  className: string,
  userClassName: string | ((state: State) => string | undefined) | undefined,
) {
  if (typeof userClassName === "function") {
    return (state: State) => cn(className, userClassName(state));
  }

  return cn(className, userClassName);
}

/* ------------------------------------------------------------------------------------------------
 * Root / Trigger / Group / Sub — structural parts. Base UI's `Menu.Root` /
 * `Menu.SubmenuRoot` don't render their own element, so these just forward props
 * and carry a `data-slot` where a DOM node exists.
 * ----------------------------------------------------------------------------------------------*/

/** Props accepted by `DropdownMenu`. */
export type DropdownMenuProps = React.ComponentProps<typeof Menu.Root>;

/**
 * `DropdownMenu` — the root that groups every part of the menu. Renders no DOM
 * element of its own. Compose with {@link DropdownMenuTrigger} and
 * {@link DropdownMenuContent}.

 *
 * @example
 * <DropdownMenu />
 */
export function DropdownMenu(props: DropdownMenuProps) {
  return <Menu.Root {...props} />;
}

/** Props accepted by `DropdownMenuTrigger`. */
export type DropdownMenuTriggerProps = React.ComponentProps<
  typeof Menu.Trigger
>;

/**
 * `DropdownMenuTrigger` — the button that opens the menu. Renders a `<button>`;
 * pass `render` to compose with your own trigger (Base UI `render` composition).

 *
 * @example
 * <DropdownMenuTrigger />
 */
export function DropdownMenuTrigger(props: DropdownMenuTriggerProps) {
  return <Menu.Trigger data-slot="dropdown-menu-trigger" {...props} />;
}

/** Props accepted by `DropdownMenuGroup`. */
export type DropdownMenuGroupProps = React.ComponentProps<typeof Menu.Group>;

/**
 * `DropdownMenuGroup` — groups related items and associates them with a
 * {@link DropdownMenuLabel}. Renders a `<div role="group">`.

 *
 * @example
 * <DropdownMenuGroup />
 */
export function DropdownMenuGroup(props: DropdownMenuGroupProps) {
  return <Menu.Group data-slot="dropdown-menu-group" {...props} />;
}

/** Props accepted by `DropdownMenuSub`. */
export type DropdownMenuSubProps = React.ComponentProps<
  typeof Menu.SubmenuRoot
>;

/**
 * `DropdownMenuSub` — the root of a nested submenu. Renders no DOM element. Wrap
 * a {@link DropdownMenuSubTrigger} and {@link DropdownMenuSubContent}.

 *
 * @example
 * <DropdownMenuSub />
 */
export function DropdownMenuSub(props: DropdownMenuSubProps) {
  return <Menu.SubmenuRoot {...props} />;
}

/** Props accepted by `DropdownMenuRadioGroup`. */
export type DropdownMenuRadioGroupProps = React.ComponentProps<
  typeof Menu.RadioGroup
>;

/**
 * `DropdownMenuRadioGroup` — wraps {@link DropdownMenuRadioItem}s for
 * single-select. Controlled via `value` / `onValueChange`.

 *
 * @example
 * <DropdownMenuRadioGroup />
 */
export function DropdownMenuRadioGroup(props: DropdownMenuRadioGroupProps) {
  return <Menu.RadioGroup data-slot="dropdown-menu-radio-group" {...props} />;
}

/* ------------------------------------------------------------------------------------------------
 * Content — Portal + Positioner + Popup, with optional Viewport wrapping and enter/exit transitions
 * driven by Base UI's `data-[starting-style]` / `data-[ending-style]` + `data-[side]`.
 * ----------------------------------------------------------------------------------------------*/

const popupClassName =
  "z-(--z-overlay) max-h-[var(--available-height)] min-w-32 max-w-[var(--available-width)] origin-[var(--transform-origin)] overflow-x-hidden overflow-y-auto rounded-lg border border-border bg-popover p-1 text-popover-foreground shadow-overlay outline-none " +
  "transition-[transform,scale,opacity] duration-fast ease-standard " +
  "data-[starting-style]:scale-95 data-[starting-style]:opacity-0 data-[ending-style]:scale-95 data-[ending-style]:opacity-0 " +
  "data-[side=top]:translate-y-1 data-[side=bottom]:-translate-y-1 data-[side=left]:translate-x-1 data-[side=right]:-translate-x-1 " +
  "data-[starting-style]:translate-x-0 data-[starting-style]:translate-y-0 data-[ending-style]:translate-x-0 data-[ending-style]:translate-y-0";

/** Props accepted by `DropdownMenuContent`. */
export interface DropdownMenuContentProps extends React.ComponentProps<
  typeof Menu.Popup
> {
  /**
   * Which side of the trigger to render against. May flip to avoid collisions.
   * @default 'bottom'
   */
  side?: Menu.Positioner.Props["side"];
  /**
   * Alignment relative to the trigger along the chosen side.
   * @default 'start'
   */
  align?: Menu.Positioner.Props["align"];
  /**
   * Distance in pixels between the trigger and the popup.
   * @default 4
   */
  sideOffset?: Menu.Positioner.Props["sideOffset"];
  /**
   * Padding from the collision boundary so the popup never touches the viewport edge.
   * @default 8
   */
  collisionPadding?: Menu.Positioner.Props["collisionPadding"];
  /** Props forwarded to the underlying Base UI `Portal`.
   * @default undefined
   */
  portalProps?: Omit<Menu.Portal.Props, "children">;
  /** Props forwarded to the underlying Base UI `Positioner`.
   * @default undefined
   */
  positionerProps?: Omit<
    Menu.Positioner.Props,
    "side" | "align" | "sideOffset" | "collisionPadding" | "children"
  >;
  /** Props forwarded to an optional Base UI `Viewport` that wraps popup children.
   * @default undefined
   */
  viewportProps?: Omit<Menu.Viewport.Props, "children">;
}

/**
 * `DropdownMenuContent` — the floating popup. Portals to `<body>`, positions
 * against the trigger, and applies enter/exit transitions. Place items, labels,
 * separators, and submenus inside it.

 *
 * @example
 * <DropdownMenuContent />
 */
export function DropdownMenuContent({
  className,
  side = "bottom",
  align = "start",
  sideOffset = FLOATING.sideOffsetAttached,
  collisionPadding = FLOATING.collisionPadding,
  portalProps,
  positionerProps,
  viewportProps,
  children,
  ...props
}: DropdownMenuContentProps) {
  const themeScope = useInternalThemeScope();
  const { className: positionerClassName, ...positionerPropsRest } =
    positionerProps ?? {};
  const { className: viewportClassName, ...viewportPropsRest } =
    viewportProps ?? {};

  return (
    <Menu.Portal {...portalProps}>
      <Menu.Positioner
        {...positionerPropsRest}
        data-slot="dropdown-menu-positioner"
        side={side}
        align={align}
        sideOffset={sideOffset}
        collisionPadding={collisionPadding}
        className={mergeStateClassName<Menu.Positioner.State>(
          cn(themeScope, "z-(--z-overlay) outline-none"),
          positionerClassName,
        )}
      >
        <Menu.Popup
          data-slot="dropdown-menu-content"
          className={cn(themeScope, popupClassName, className)}
          {...props}
        >
          {viewportProps ? (
            <Menu.Viewport
              {...viewportPropsRest}
              data-slot="dropdown-menu-viewport"
              className={mergeStateClassName<Menu.Viewport.State>(
                themeScope ?? "",
                viewportClassName,
              )}
            >
              {children}
            </Menu.Viewport>
          ) : (
            children
          )}
        </Menu.Popup>
      </Menu.Positioner>
    </Menu.Portal>
  );
}

/* ------------------------------------------------------------------------------------------------
 * Item — interactive row, with `variant="destructive"` (CVA) + `inset` spacing.
 * Highlighted state (keyboard nav / hover) is Base UI's `data-highlighted`.
 * ----------------------------------------------------------------------------------------------*/

export const dropdownMenuItemVariants = cva(
  "group/dropdown-menu-item relative flex items-center gap-2 rounded-sm px-2 py-1.5 text-base outline-none select-none data-[disabled]:pointer-events-none data-[disabled]:opacity-(--opacity-dim) data-[inset]:ps-8 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-(--icon-default)",
  {
    variants: {
      variant: {
        default:
          "text-popover-foreground [&_svg]:text-muted-foreground data-[highlighted]:bg-accent data-[highlighted]:text-accent-foreground data-[highlighted]:[&_svg]:text-accent-foreground",
        destructive:
          "text-destructive-text [&_svg]:text-destructive-text data-[highlighted]:bg-destructive-subtle data-[highlighted]:text-destructive-text",
      },
    },
    defaultVariants: { variant: "default" },
  },
);

/** Props accepted by `DropdownMenuItem`. */
export interface DropdownMenuItemProps
  extends
    React.ComponentProps<typeof Menu.Item>,
    VariantProps<typeof dropdownMenuItemVariants> {
  /**
   * Adds inline-start padding so the label aligns with items that have a leading icon
   * or indicator.
   * @default false
   */
  inset?: boolean;
}

/**
 * `DropdownMenuItem` — a selectable action. Use `variant="destructive"` for
 * delete/remove actions and `inset` to align with checkbox/radio rows. Closes
 * the menu on click by default.

 *
 * @example
 * <DropdownMenuItem />
 */
export function DropdownMenuItem({
  className,
  variant = "default",
  inset,
  ...props
}: DropdownMenuItemProps) {
  return (
    <Menu.Item
      data-slot="dropdown-menu-item"
      data-variant={variant}
      data-inset={inset ? "" : undefined}
      className={cn(dropdownMenuItemVariants({ variant }), className)}
      {...props}
    />
  );
}

/* ------------------------------------------------------------------------------------------------
 * Checkbox + Radio items — leading indicator slot, toggled/selected via
 * `data-checked`. Indicators render the check/dot only when active.
 * ----------------------------------------------------------------------------------------------*/

const choiceItemClassName =
  "group/dropdown-menu-item relative flex items-center gap-2 rounded-sm py-1.5 pe-2 ps-8 text-base text-popover-foreground outline-none select-none data-[disabled]:pointer-events-none data-[disabled]:opacity-(--opacity-dim) data-[highlighted]:bg-accent data-[highlighted]:text-accent-foreground [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-(--icon-default)";

/** Props accepted by `DropdownMenuCheckboxItem`. */
export type DropdownMenuCheckboxItemProps = React.ComponentProps<
  typeof Menu.CheckboxItem
>;

/**
 * `DropdownMenuCheckboxItem` — a togglable item with a check indicator. Control
 * with `checked` / `onCheckedChange`. Stays open on click by default.

 *
 * @example
 * <DropdownMenuCheckboxItem />
 */
export function DropdownMenuCheckboxItem({
  className,
  children,
  ...props
}: DropdownMenuCheckboxItemProps) {
  return (
    <Menu.CheckboxItem
      data-slot="dropdown-menu-checkbox-item"
      className={cn(choiceItemClassName, className)}
      {...props}
    >
      <span className="pointer-events-none absolute start-2 flex size-(--icon-default) items-center justify-center">
        <Menu.CheckboxItemIndicator>
          <CheckIcon className="size-(--icon-default) text-foreground" />
        </Menu.CheckboxItemIndicator>
      </span>
      {children}
    </Menu.CheckboxItem>
  );
}

/** Props accepted by `DropdownMenuRadioItem`. */
export type DropdownMenuRadioItemProps = React.ComponentProps<
  typeof Menu.RadioItem
>;

/**
 * `DropdownMenuRadioItem` — one option in a {@link DropdownMenuRadioGroup}, with
 * a filled-dot indicator when selected.

 *
 * @example
 * <DropdownMenuRadioItem />
 */
export function DropdownMenuRadioItem({
  className,
  children,
  ...props
}: DropdownMenuRadioItemProps) {
  return (
    <Menu.RadioItem
      data-slot="dropdown-menu-radio-item"
      className={cn(choiceItemClassName, className)}
      {...props}
    >
      <span className="pointer-events-none absolute start-2 flex size-(--icon-default) items-center justify-center">
        <Menu.RadioItemIndicator>
          <CircleIcon className="size-2 fill-current text-foreground" />
        </Menu.RadioItemIndicator>
      </span>
      {children}
    </Menu.RadioItem>
  );
}

/* ------------------------------------------------------------------------------------------------
 * Label / Separator / Shortcut — non-interactive chrome.
 * ----------------------------------------------------------------------------------------------*/

/** Props accepted by `DropdownMenuLabel`. */
export interface DropdownMenuLabelProps extends React.ComponentProps<
  typeof Menu.GroupLabel
> {
  /**
   * Indents the label to line up with inset items.
   * @default false
   */
  inset?: boolean;
}

/**
 * `DropdownMenuLabel` — a non-interactive heading for a {@link DropdownMenuGroup}
 * or {@link DropdownMenuRadioGroup}. Renders Base UI's `GroupLabel` so it's
 * announced as the group's accessible name.

 *
 * @example
 * <DropdownMenuLabel />
 */
export function DropdownMenuLabel({
  className,
  inset,
  ...props
}: DropdownMenuLabelProps) {
  return (
    <Menu.GroupLabel
      data-slot="dropdown-menu-label"
      data-inset={inset ? "" : undefined}
      className={cn(
        "px-2 py-1.5 text-label-sm text-muted-foreground data-[inset]:ps-8",
        className,
      )}
      {...props}
    />
  );
}

/** Props accepted by `DropdownMenuSeparator`. */
export type DropdownMenuSeparatorProps = React.ComponentProps<
  typeof Menu.Separator
>;

/**
 * `DropdownMenuSeparator` — a thin divider between item groups. Renders a
 * `<div role="separator">`.

 *
 * @example
 * <DropdownMenuSeparator />
 */
export function DropdownMenuSeparator({
  className,
  ...props
}: DropdownMenuSeparatorProps) {
  return (
    <Menu.Separator
      data-slot="dropdown-menu-separator"
      className={cn("-mx-1 my-1 h-px bg-border", className)}
      {...props}
    />
  );
}

/** Props accepted by `DropdownMenuShortcut`. */
export type DropdownMenuShortcutProps = React.ComponentProps<"span">;

/**
 * `DropdownMenuShortcut` — inline-end-aligned keyboard-shortcut hint inside an item
 * (e.g. `⌘K`). Purely visual; use the item's own keybinding for behavior.

 *
 * @example
 * <DropdownMenuShortcut />
 */
export function DropdownMenuShortcut({
  className,
  ...props
}: DropdownMenuShortcutProps) {
  return (
    <span
      data-slot="dropdown-menu-shortcut"
      className={cn(
        "ms-auto text-mono-label text-muted-foreground group-data-[highlighted]/dropdown-menu-item:text-accent-foreground group-data-[variant=destructive]/dropdown-menu-item:text-destructive-text group-data-[variant=destructive]/dropdown-menu-item:group-data-[highlighted]/dropdown-menu-item:text-destructive-text",
        className,
      )}
      {...props}
    />
  );
}

/* ------------------------------------------------------------------------------------------------
 * Submenu trigger + content.
 * ----------------------------------------------------------------------------------------------*/

/** Props accepted by `DropdownMenuSubTrigger`. */
export interface DropdownMenuSubTriggerProps extends React.ComponentProps<
  typeof Menu.SubmenuTrigger
> {
  /**
   * Indents the trigger to align with inset items.
   * @default false
   */
  inset?: boolean;
}

/**
 * `DropdownMenuSubTrigger` — the item that opens a nested submenu, with a
 * trailing chevron. Highlighted/open states use `data-highlighted` /
 * `data-popup-open`.

 *
 * @example
 * <DropdownMenuSubTrigger />
 */
export function DropdownMenuSubTrigger({
  className,
  inset,
  children,
  ...props
}: DropdownMenuSubTriggerProps) {
  return (
    <Menu.SubmenuTrigger
      data-slot="dropdown-menu-sub-trigger"
      data-inset={inset ? "" : undefined}
      className={cn(
        "group/dropdown-menu-item relative flex items-center gap-2 rounded-sm px-2 py-1.5 text-base text-popover-foreground outline-none select-none data-[disabled]:pointer-events-none data-[disabled]:opacity-(--opacity-dim) data-[inset]:ps-8 data-[highlighted]:bg-accent data-[highlighted]:text-accent-foreground data-[popup-open]:bg-accent data-[popup-open]:text-accent-foreground [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg]:text-muted-foreground [&_svg:not([class*='size-'])]:size-(--icon-default) data-[highlighted]:[&_svg]:text-accent-foreground data-[popup-open]:[&_svg]:text-accent-foreground",
        className,
      )}
      {...props}
    >
      {children}
      <ChevronRightIcon className="ms-auto rtl:rotate-180" />
    </Menu.SubmenuTrigger>
  );
}

/** Props accepted by `DropdownMenuSubContent`. */
export type DropdownMenuSubContentProps = DropdownMenuContentProps;

/**
 * `DropdownMenuSubContent` — the nested popup opened by a
 * {@link DropdownMenuSubTrigger}. Defaults to opening to the right of its parent.

 *
 * @example
 * <DropdownMenuSubContent />
 */
export function DropdownMenuSubContent({
  side = "right",
  align = "start",
  sideOffset = 0,
  ...props
}: DropdownMenuSubContentProps) {
  return (
    <DropdownMenuContent
      side={side}
      align={align}
      sideOffset={sideOffset}
      {...props}
    />
  );
}

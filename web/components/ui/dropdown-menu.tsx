"use client";

import * as React from "react";
import { Menu } from "@base-ui/react/menu";
import { FLOATING } from "@vegastack/design";
import {
  createMenuParts,
  FloatingSurface,
  type MenuPartCheckboxItemProps,
  type MenuPartContentProps,
  type MenuPartGroupProps,
  type MenuPartItemProps,
  type MenuPartLabelProps,
  type MenuPartRadioGroupProps,
  type MenuPartRadioItemProps,
  type MenuPartSeparatorProps,
  type MenuPartShortcutProps,
  type MenuPartSubTriggerProps,
} from "@/components/ui/floating-surface";

/* ------------------------------------------------------------------------------------------------
 * DropdownMenu — a button-triggered action menu on Base UI's `Menu`.
 *
 * Everything below the trigger — the popup surface, and every row inside it — comes from the
 * shared `floating-surface` module. `DropdownMenu` and `ContextMenu` differ only in how they open
 * (audit B3-01 / B3-02), so this file owns the root, the trigger, and the popup's positioning
 * defaults; nothing else.
 * ----------------------------------------------------------------------------------------------*/

const parts = createMenuParts("dropdown-menu");

/** Props accepted by `DropdownMenu`. */
export type DropdownMenuProps = React.ComponentProps<typeof Menu.Root>;

/**
 * `DropdownMenu` — the root that groups every part of the menu. Renders no DOM element of its own.
 * Compose with {@link DropdownMenuTrigger} and {@link DropdownMenuContent}.
 *
 * @example
 * <DropdownMenu>
 *   <DropdownMenuTrigger render={<Button variant="outline">Actions</Button>} />
 *   <DropdownMenuContent>
 *     <DropdownMenuItem>Rename</DropdownMenuItem>
 *     <DropdownMenuItem tone="destructive">Delete</DropdownMenuItem>
 *   </DropdownMenuContent>
 * </DropdownMenu>
 */
export function DropdownMenu(props: DropdownMenuProps) {
  return <Menu.Root {...props} />;
}

/** Props accepted by `DropdownMenuTrigger`. */
export type DropdownMenuTriggerProps = React.ComponentProps<
  typeof Menu.Trigger
>;

/**
 * `DropdownMenuTrigger` — the button that opens the menu. Renders a `<button>`; pass `render` to
 * compose with your own trigger (Base UI `render` composition).
 *
 * @example
 * <DropdownMenuTrigger />
 */
export function DropdownMenuTrigger(props: DropdownMenuTriggerProps) {
  return <Menu.Trigger data-slot="dropdown-menu-trigger" {...props} />;
}

/** Props accepted by `DropdownMenuGroup`. */
export type DropdownMenuGroupProps = MenuPartGroupProps;

/**
 * `DropdownMenuGroup` — groups related items and associates them with a
 * {@link DropdownMenuLabel}. Renders a `<div role="group">`.
 *
 * @example
 * <DropdownMenuGroup />
 */
export const DropdownMenuGroup = parts.Group;

/** Props accepted by `DropdownMenuSub`. */
export type DropdownMenuSubProps = React.ComponentProps<
  typeof Menu.SubmenuRoot
>;

/**
 * `DropdownMenuSub` — the root of a nested submenu. Renders no DOM element. Wrap a
 * {@link DropdownMenuSubTrigger} and {@link DropdownMenuSubContent}.
 *
 * @example
 * <DropdownMenuSub />
 */
export const DropdownMenuSub = Menu.SubmenuRoot;

/** Props accepted by `DropdownMenuRadioGroup`. */
export type DropdownMenuRadioGroupProps = MenuPartRadioGroupProps;

/**
 * `DropdownMenuRadioGroup` — wraps {@link DropdownMenuRadioItem}s for single-select. Controlled via
 * `value` / `onValueChange`.
 *
 * @example
 * <DropdownMenuRadioGroup />
 */
export const DropdownMenuRadioGroup = parts.RadioGroup;

/** Props accepted by `DropdownMenuContent`. */
export interface DropdownMenuContentProps extends MenuPartContentProps {
  /**
   * Props forwarded to an optional Base UI `Viewport` that wraps popup children.
   * @default undefined
   */
  viewportProps?: Omit<Menu.Viewport.Props, "children">;
}

/**
 * `DropdownMenuContent` — the floating popup. Portals to `<body>`, positions against the trigger,
 * and applies the shared `menu` surface and its D11 enter/exit motion. Place items, labels,
 * separators, and submenus inside it.
 *
 * @example
 * <DropdownMenuContent />
 */
export function DropdownMenuContent({
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
  return (
    <FloatingSurface
      parts={{
        Portal: Menu.Portal,
        Positioner: Menu.Positioner,
        Popup: Menu.Popup,
        Viewport: Menu.Viewport,
      }}
      slot="dropdown-menu"
      surface="menu"
      positioning={{ side, align, sideOffset, collisionPadding }}
      portalProps={portalProps}
      positionerProps={positionerProps}
      viewportProps={viewportProps}
      popupProps={props}
    >
      {children}
    </FloatingSurface>
  );
}

/** Props accepted by `DropdownMenuItem`. */
export type DropdownMenuItemProps = MenuPartItemProps;

/**
 * `DropdownMenuItem` — a selectable action. Use `tone="destructive"` for delete/remove actions and
 * `inset` to align with checkbox/radio rows. Closes the menu on click by default.
 *
 * @example
 * <DropdownMenuItem tone="destructive">Delete</DropdownMenuItem>
 */
export const DropdownMenuItem = parts.Item;

/** Props accepted by `DropdownMenuCheckboxItem`. */
export type DropdownMenuCheckboxItemProps = MenuPartCheckboxItemProps;

/**
 * `DropdownMenuCheckboxItem` — a togglable item with a check indicator. Control with `checked` /
 * `onCheckedChange`. Stays open on click by default.
 *
 * @example
 * <DropdownMenuCheckboxItem checked>Show grid</DropdownMenuCheckboxItem>
 */
export const DropdownMenuCheckboxItem = parts.CheckboxItem;

/** Props accepted by `DropdownMenuRadioItem`. */
export type DropdownMenuRadioItemProps = MenuPartRadioItemProps;

/**
 * `DropdownMenuRadioItem` — one option in a {@link DropdownMenuRadioGroup}, with a filled-dot
 * indicator when selected.
 *
 * @example
 * <DropdownMenuRadioItem value="list">List</DropdownMenuRadioItem>
 */
export const DropdownMenuRadioItem = parts.RadioItem;

/** Props accepted by `DropdownMenuLabel`. */
export type DropdownMenuLabelProps = MenuPartLabelProps;

/**
 * `DropdownMenuLabel` — a non-interactive heading for a {@link DropdownMenuGroup} or
 * {@link DropdownMenuRadioGroup}. Renders Base UI's `GroupLabel`, so it is announced as the
 * group's accessible name.
 *
 * @example
 * <DropdownMenuLabel>View</DropdownMenuLabel>
 */
export const DropdownMenuLabel = parts.Label;

/** Props accepted by `DropdownMenuSeparator`. */
export type DropdownMenuSeparatorProps = MenuPartSeparatorProps;

/**
 * `DropdownMenuSeparator` — a thin divider between item groups. Renders a
 * `<div role="separator">`.
 *
 * @example
 * <DropdownMenuSeparator />
 */
export const DropdownMenuSeparator = parts.Separator;

/** Props accepted by `DropdownMenuShortcut`. */
export type DropdownMenuShortcutProps = MenuPartShortcutProps;

/**
 * `DropdownMenuShortcut` — inline-end-aligned keyboard-shortcut hint inside an item (e.g. `⌘K`).
 * Purely visual; use the item's own keybinding for behavior.
 *
 * @example
 * <DropdownMenuShortcut>⌘K</DropdownMenuShortcut>
 */
export const DropdownMenuShortcut = parts.Shortcut;

/** Props accepted by `DropdownMenuSubTrigger`. */
export type DropdownMenuSubTriggerProps = MenuPartSubTriggerProps;

/**
 * `DropdownMenuSubTrigger` — the item that opens a nested submenu, with a trailing chevron.
 * Highlighted/open states use `data-highlighted` / `data-popup-open`.
 *
 * @example
 * <DropdownMenuSubTrigger>Share</DropdownMenuSubTrigger>
 */
export const DropdownMenuSubTrigger = parts.SubTrigger;

/** Props accepted by `DropdownMenuSubContent`. */
export type DropdownMenuSubContentProps = DropdownMenuContentProps;

/**
 * `DropdownMenuSubContent` — the nested popup opened by a {@link DropdownMenuSubTrigger}. Defaults
 * to opening flush to the right of its parent.
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

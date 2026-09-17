"use client";

import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { Input as BaseInput } from "@base-ui/react/input";
import { Menu } from "@base-ui/react/menu";
import { CheckIcon, ChevronRightIcon, CircleIcon, Search } from "lucide-react";
import { cn } from "@vegastack/design";
import { useInternalThemeScope } from "@vegastack/design/theme-scope";

/* ------------------------------------------------------------------------------------------------
 * floating-surface — the ONE module every anchored overlay and every list surface composes.
 *
 * Before this module, popover, hover-card, tooltip, dropdown-menu, context-menu, select, combobox
 * and navigation-menu each carried their own copy of the same four things (audit 2026-09-07, B3-01):
 * a `mergeStateClassName` helper, a `Portal → Positioner → Popup (→ Viewport)` composition, the
 * theme-scope plumbing that keeps a portaled surface inside its semantic scope, and the enter/exit
 * motion pair. Four more restated one list-item look four ways (B3-06), and four restated the
 * "search inside a panel" chrome three ways (B8-04 / B9-11). This is the single authority for all
 * three.
 *
 * It stays deliberately un-opinionated about WHICH Base UI namespace it renders: each overlay hands
 * its own `Portal`/`Positioner`/`Popup`/`Viewport` parts in through `parts`, so the public prop
 * types of `PopoverContent`, `SelectContent`, … keep referring to their own Base UI part types with
 * no loss of precision. Only the internal hand-off is structural.
 *
 * The menu parts are the one exception, and deliberately so: Base UI's `ContextMenu` namespace
 * re-exports `MenuItem`, `MenuCheckboxItem`, `MenuRadioItem`, `MenuGroupLabel`, `MenuSubmenuTrigger`
 * and `Separator` verbatim from its `Menu` namespace (`@base-ui/react/context-menu`
 * `index.parts.js`), so one implementation is not a convenience — it is the same component.
 * `createMenuParts(prefix)` binds that one implementation to a component's `data-slot` prefix.
 * ----------------------------------------------------------------------------------------------*/

/**
 * Merges a system class string with a user `className` that may itself be Base UI's
 * `(state) => string` form. Base UI parts accept both shapes; every floating part needs to compose
 * ours with the consumer's without collapsing the state function.
 *
 * @example
 * className={mergeStateClassName(FLOATING_POSITIONER, positionerProps?.className)}
 */
export function mergeStateClassName<State>(
  className: string,
  userClassName: string | ((state: State) => string | undefined) | undefined,
): string | ((state: State) => string) {
  if (typeof userClassName === "function") {
    return (state: State) => cn(className, userClassName(state));
  }

  return cn(className, userClassName);
}

/**
 * The positioner class shared by every anchored overlay: the overlay z-band, and no focus outline
 * on a container that is never itself focusable (the popup inside it keeps the global indicator).
 */
export const FLOATING_POSITIONER = "z-(--z-overlay) outline-none";

/**
 * The four floating popup recipes. All four share the overlay z-band, the Base UI transform origin,
 * and the D11 enter/exit pair (scale .95 + fade). They differ only in the surface they paint.
 *
 * - `panel` — a bordered popover panel at the 16px popover tier (Popover, HoverCard). D14.
 * - `menu` — the same surface at list density (4px), scroll-capped to the available height
 *   (DropdownMenu, ContextMenu, Select, Combobox, Command).
 * - `tooltip` — the inverted ink chip (Tooltip).
 * - `navigation` — the bordered panel with no padding, sized by NavigationMenu's runtime vars.
 *
 * `motion` picks the D11 duration: `fast` (150ms) for every floating surface, `base` (200ms) for
 * the one large morphing panel (NavigationMenu resizes between items, which reads wrong at 150ms).
 */
export const floatingPopupVariants = cva(
  "z-(--z-overlay) origin-(--transform-origin) data-[starting-style]:scale-95 data-[starting-style]:opacity-0 data-[ending-style]:scale-95 data-[ending-style]:opacity-0",
  {
    variants: {
      surface: {
        panel:
          "w-(--panel-width-md) max-w-[calc(100vw-var(--spacing)*8)] rounded-lg border border-border bg-popover p-4 text-base text-popover-foreground shadow-overlay",
        menu: [
          "max-h-[var(--available-height)] min-w-32 max-w-[var(--available-width)]",
          "overflow-x-hidden overflow-y-auto overscroll-contain",
          "rounded-lg border border-border bg-popover p-1 text-popover-foreground shadow-overlay outline-none",
          // Menus nudge in from the side they opened against; the starting/ending offsets below
          // reset it so the popup settles flush.
          "data-[side=top]:translate-y-1 data-[side=bottom]:-translate-y-1 data-[side=left]:translate-x-1 data-[side=right]:-translate-x-1",
          "data-[starting-style]:translate-x-0 data-[starting-style]:translate-y-0 data-[ending-style]:translate-x-0 data-[ending-style]:translate-y-0",
        ].join(" "),
        tooltip:
          "flex w-fit max-w-xs items-center gap-2 rounded-md bg-foreground px-2.5 py-1 text-sm text-background shadow-overlay select-none data-[instant]:duration-0",
        navigation:
          "h-(--popup-height) w-full rounded-lg border border-border bg-popover text-popover-foreground shadow-overlay data-[starting-style]:-translate-y-px sm:w-(--popup-width)",
      },
      motion: {
        // `scale` is listed explicitly — Tailwind v4's `scale-*` sets the CSS `scale` property,
        // which `transform` does not cover.
        fast: "transition-[transform,scale,opacity] duration-fast ease-standard",
        base: "transition-[transform,scale,opacity,width,height] duration-base ease-standard",
      },
    },
    defaultVariants: { surface: "panel", motion: "fast" },
  },
);

/** The floating popup surface recipes `FloatingSurface` can paint. */
export type FloatingSurfaceVariant = NonNullable<
  VariantProps<typeof floatingPopupVariants>["surface"]
>;

/**
 * Structural view of a Base UI floating namespace. Each overlay passes its OWN parts, so the parts
 * stay the real Base UI components; only this hand-off is structural.
 */
export interface FloatingSurfaceParts {
  /** The namespace's `Portal` — mounts the surface outside the trigger's DOM subtree. */
  Portal: React.ElementType;
  /** The namespace's `Positioner` — owns side/align/offset/collision. */
  Positioner: React.ElementType;
  /** The namespace's `Popup` — the painted surface. */
  Popup: React.ElementType;
  /**
   * The namespace's `Viewport`, when it has one.
   * @default undefined
   */
  Viewport?: React.ElementType;
}

/**
 * The structural shape a Base UI floating part is handed. Deliberately open: it names only the two
 * members this module reads (`className`, in either of Base UI's two forms, and `children`) and
 * lets every other prop pass through unread, so an overlay can forward its own Base UI part props
 * without them being narrowed here.
 */
type FloatingPartProps = {
  className?: string | ((state: never) => string | undefined);
  children?: React.ReactNode;
};

/**
 * A bag of Base UI part props forwarded verbatim, with nothing in it read here. Deliberately
 * `object` rather than `Record<string, unknown>`: Base UI's part-prop types are interfaces, and TS
 * only infers an implicit index signature for object-literal types, so a `Record` target would
 * reject every real Base UI prop type.
 */
type FloatingPassthroughProps = object;

/** Props accepted by `FloatingSurface`. */
export interface FloatingSurfaceProps extends VariantProps<
  typeof floatingPopupVariants
> {
  /** The Base UI namespace parts this surface renders. */
  parts: FloatingSurfaceParts;
  /**
   * The component's `data-slot` prefix — `"popover"` yields `popover-positioner`,
   * `popover-content` and `popover-viewport`.
   */
  slot: string;
  /**
   * Overrides the popup's `data-slot` when the component's popup is not called `<slot>-content`
   * (NavigationMenu's is `navigation-menu-popup`).
   * @default `${slot}-content`
   */
  popupSlot?: string;
  /**
   * Positioning props forwarded to the `Positioner` (side, align, sideOffset, …).
   * @default undefined
   */
  positioning?: FloatingPassthroughProps;
  /**
   * Props forwarded to the `Portal`.
   * @default undefined
   */
  portalProps?: FloatingPassthroughProps;
  /**
   * Extra props forwarded to the `Positioner`, merged after `positioning`.
   * @default undefined
   */
  positionerProps?: FloatingPartProps;
  /**
   * Props forwarded to the `Popup` — this is where the consumer's own props land.
   * @default undefined
   */
  popupProps?: FloatingPartProps;
  /**
   * Props forwarded to the `Viewport`.
   * @default undefined
   */
  viewportProps?: FloatingPartProps;
  /**
   * When to render the `Viewport`. `"auto"` renders it only when `viewportProps` is supplied and
   * wraps `children` in it; `"always"` renders an empty `Viewport` as the popup's only child (the
   * NavigationMenu shape, where Base UI projects each item's content into it).
   * @default "auto"
   */
  viewport?: "auto" | "always";
  /**
   * Extra classes for the popup, appended after the recipe.
   * @default undefined
   */
  className?: string;
  /**
   * An arrow element rendered as the popup's first child.
   * @default undefined
   */
  arrow?: React.ReactNode;
  /**
   * The popup's content.
   * @default undefined
   */
  children?: React.ReactNode;
}

/**
 * `FloatingSurface` — composes a Base UI floating namespace's `Portal → Positioner → Popup
 * (→ Viewport)` into one element, paints the shared surface recipe, applies the D11 enter/exit
 * motion, and carries the internal theme scope across the portal boundary so a portaled overlay
 * inside a `MarketingSurface` keeps that scope's tokens.
 *
 * @example
 * <FloatingSurface
 *   parts={{ Portal: Popover.Portal, Positioner: Popover.Positioner, Popup: Popover.Popup }}
 *   slot="popover"
 *   surface="panel"
 *   positioning={{ side, sideOffset, align, collisionPadding }}
 *   popupProps={props}
 * >
 *   {children}
 * </FloatingSurface>
 */
export function FloatingSurface({
  parts,
  slot,
  popupSlot,
  surface = "panel",
  motion = "fast",
  positioning,
  portalProps,
  positionerProps,
  popupProps,
  viewportProps,
  viewport = "auto",
  className,
  arrow,
  children,
}: FloatingSurfaceProps) {
  const themeScope = useInternalThemeScope();
  const { Portal, Positioner, Popup, Viewport } = parts as {
    Portal: React.ComponentType<FloatingPartProps>;
    Positioner: React.ComponentType<FloatingPartProps>;
    Popup: React.ComponentType<FloatingPartProps>;
    Viewport?: React.ComponentType<FloatingPartProps>;
  };
  const { className: positionerClassName, ...positionerRest } =
    positionerProps ?? {};
  const { className: popupClassName, ...popupRest } = popupProps ?? {};
  const { className: viewportClassName, ...viewportRest } = viewportProps ?? {};

  const renderViewport = viewport === "always" || Boolean(viewportProps);
  const viewportElement =
    Viewport && renderViewport ? (
      <Viewport
        data-slot={`${slot}-viewport`}
        {...viewportRest}
        className={mergeStateClassName(
          cn(
            themeScope,
            viewport === "always"
              ? "relative h-full w-full overflow-hidden"
              : "",
          ),
          viewportClassName,
        )}
      >
        {viewport === "always" ? undefined : children}
      </Viewport>
    ) : null;

  return (
    <Portal {...portalProps}>
      <Positioner
        {...positioning}
        data-slot={`${slot}-positioner`}
        {...positionerRest}
        className={mergeStateClassName(
          cn(themeScope, FLOATING_POSITIONER),
          positionerClassName,
        )}
      >
        <Popup
          // The slot is a DEFAULT, not an override: a composing component (`EmojiPicker`,
          // `DatePicker`, `ColorPicker`) names its own popup by passing `data-slot` through, and
          // its tests and contract routes select on that name. Spreading after the default is what
          // lets it win.
          data-slot={popupSlot ?? `${slot}-content`}
          {...popupRest}
          className={mergeStateClassName(
            cn(
              themeScope,
              floatingPopupVariants({ surface, motion }),
              className,
            ),
            popupClassName,
          )}
        >
          {arrow}
          {viewportElement ?? children}
        </Popup>
      </Positioner>
    </Portal>
  );
}

/** Props accepted by `FloatingArrow`. */
export interface FloatingArrowProps {
  /**
   * The namespace's `Arrow` part. Named `element` rather than `part` because React's DOM typings
   * already claim `part` (CSS Shadow Parts) on every element the arrow can render.
   */
  element: React.ElementType;
  /** The arrow's `data-slot`. */
  slot: string;
  /**
   * `panel` draws the bordered popover wedge; `tooltip` the smaller inverted-ink one.
   * @default "panel"
   */
  tone?: "panel" | "tooltip";
  /**
   * Extra classes for the arrow wrapper — Base UI's `(state) => string` form included.
   * @default undefined
   */
  className?: string | ((state: never) => string | undefined);
}

/**
 * `FloatingArrow` — the shared directional wedge. Popover and HoverCard draw the bordered popover
 * variant; Tooltip draws the smaller inverted one. The wedge is a rotated square whose two visible
 * edges carry the hairline, so it reads as an extension of the surface rather than a separate glyph.
 *
 * @example
 * <FloatingArrow element={Popover.Arrow} slot="popover-arrow" />
 */
export function FloatingArrow({
  element,
  slot,
  tone = "panel",
  className,
  ...props
}: FloatingArrowProps & FloatingPassthroughProps) {
  const Arrow = element as React.ComponentType<FloatingPartProps>;
  return (
    <Arrow
      data-slot={slot}
      {...props}
      className={mergeStateClassName(
        tone === "panel"
          ? "data-[side=bottom]:-top-1.5 data-[side=top]:-bottom-1.5 data-[side=left]:-right-1.5 data-[side=right]:-left-1.5"
          : "data-[side=bottom]:-top-1 data-[side=top]:-bottom-1 data-[side=left]:-right-1 data-[side=right]:-left-1",
        className,
      )}
    >
      <span
        className={
          tone === "panel"
            ? "block size-2.5 rotate-45 rounded-xs border-r border-b border-border bg-popover"
            : "block size-2 rotate-45 rounded-xs bg-foreground"
        }
      />
    </Arrow>
  );
}

/* ------------------------------------------------------------------------------------------------
 * menuItemVariants — the ONE list-item recipe.
 *
 * Menu items, checkbox/radio items, submenu triggers, select options, combobox options and command
 * rows all expressed the same row four different ways (audit B3-06). They are one recipe now, and
 * the highlight climbs the surface ladder: rung 2 on `data-highlighted` (Base UI sets it for both
 * pointer hover and keyboard navigation), rung 3 when pressed or selected. Radius `md` inside the
 * list's 4px padding keeps every wash inset from the popup hairline (SP-02) and concentric with the
 * popup's `lg` corner (12 = 8 + 4).
 * ----------------------------------------------------------------------------------------------*/

/**
 * The one list-item recipe behind menu items, checkbox/radio items, submenu triggers, select
 * options, combobox options and command rows.
 */
export const menuItemVariants = cva(
  [
    "group/menu-item relative flex w-full items-center gap-2 rounded-md text-base outline-none select-none",
    "data-[disabled]:pointer-events-none data-[disabled]:opacity-(--opacity-dim)",
    "data-[inset]:ps-8",
    "[&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-(--icon-default)",
  ].join(" "),
  {
    variants: {
      tone: {
        default: [
          "text-popover-foreground [&_svg]:text-muted-foreground",
          "data-[highlighted]:bg-surface-2 data-[popup-open]:bg-surface-2",
          "data-[highlighted]:[&_svg]:text-foreground data-[popup-open]:[&_svg]:text-foreground",
          "active:bg-surface-3 data-[selected]:bg-surface-3 data-[highlighted]:data-[selected]:bg-surface-3",
        ].join(" "),
        destructive: [
          "text-destructive-text [&_svg]:text-destructive-text",
          "data-[highlighted]:bg-destructive/(--alpha-hover) active:bg-destructive/(--alpha-pressed)",
        ].join(" "),
      },
      indicator: {
        none: "",
        /** Leading check/dot indicator well (menus). */
        leading: "ps-8",
        /** Trailing check indicator well (select, combobox). */
        trailing: "pe-8",
      },
      size: {
        md: "px-2 py-1.5",
        lg: "px-3 py-2",
      },
    },
    defaultVariants: { tone: "default", indicator: "none", size: "md" },
  },
);

/** The list-item recipe's variant props. */
export type MenuItemVariantProps = VariantProps<typeof menuItemVariants>;

/** The tones a list item can carry. */
export type MenuItemTone = NonNullable<MenuItemVariantProps["tone"]>;

/** `menuLabelClassName` — the non-interactive group heading shared by every list surface. */
export const menuLabelClassName =
  "px-2 py-1.5 text-label-sm text-muted-foreground data-[inset]:ps-8";

/** `menuSeparatorClassName` — the divider between item groups, bled to the list's 4px padding. */
export const menuSeparatorClassName = "-mx-1 my-1 h-px bg-border";

/**
 * `menuShortcutClassName` — the trailing keyboard hint inside a list item. It reads as secondary
 * ink in every state: the P1 ladder tints the row's background, never its text, so the hint no
 * longer has to restate a highlighted colour.
 */
export const menuShortcutClassName =
  "ms-auto text-mono-label text-muted-foreground group-data-[tone=destructive]/menu-item:text-destructive-text";

/** `menuIndicatorWellClassName` — the fixed leading well a check or dot indicator sits in. */
export const menuIndicatorWellClassName =
  "pointer-events-none absolute start-2 flex size-(--icon-default) items-center justify-center";

/** Props accepted by a shared menu `Item`. */
export interface MenuPartItemProps extends React.ComponentProps<
  typeof Menu.Item
> {
  /**
   * `destructive` tints the row for delete/remove actions.
   * @default "default"
   */
  tone?: MenuItemTone;
  /**
   * Adds inline-start padding so the label aligns with rows that carry a leading indicator.
   * @default false
   */
  inset?: boolean;
}

/** Props accepted by a shared menu `CheckboxItem`. */
export type MenuPartCheckboxItemProps = React.ComponentProps<
  typeof Menu.CheckboxItem
>;

/** Props accepted by a shared menu `RadioItem`. */
export type MenuPartRadioItemProps = React.ComponentProps<
  typeof Menu.RadioItem
>;

/** Props accepted by a shared menu `Label`. */
export interface MenuPartLabelProps extends React.ComponentProps<
  typeof Menu.GroupLabel
> {
  /**
   * Indents the label to line up with inset rows.
   * @default false
   */
  inset?: boolean;
}

/** Props accepted by a shared menu `Separator`. */
export type MenuPartSeparatorProps = React.ComponentProps<
  typeof Menu.Separator
>;

/** Props accepted by a shared menu `Shortcut`. */
export type MenuPartShortcutProps = React.ComponentProps<"span">;

/** Props accepted by a shared menu `SubTrigger`. */
export interface MenuPartSubTriggerProps extends React.ComponentProps<
  typeof Menu.SubmenuTrigger
> {
  /**
   * Indents the trigger to line up with inset rows.
   * @default false
   */
  inset?: boolean;
}

/**
 * Props accepted by a shared menu popup. Both menu components position an identical Base UI
 * `Menu.Positioner` (ContextMenu re-exports it), so the positioning surface is declared once.
 */
export interface MenuPartContentProps extends React.ComponentProps<
  typeof Menu.Popup
> {
  /**
   * Which side of the anchor to render against. May flip to avoid collisions.
   * @default 'bottom'
   */
  side?: Menu.Positioner.Props["side"];
  /**
   * Alignment relative to the anchor along the chosen side.
   * @default 'start'
   */
  align?: Menu.Positioner.Props["align"];
  /**
   * Distance in pixels between the anchor and the popup.
   * @default 4
   */
  sideOffset?: Menu.Positioner.Props["sideOffset"];
  /**
   * Padding from the collision boundary so the popup never touches the viewport edge.
   * @default 8
   */
  collisionPadding?: Menu.Positioner.Props["collisionPadding"];
  /**
   * Props forwarded to the underlying Base UI `Portal`.
   * @default undefined
   */
  portalProps?: Omit<Menu.Portal.Props, "children">;
  /**
   * Props forwarded to the underlying Base UI `Positioner`.
   * @default undefined
   */
  positionerProps?: Omit<
    Menu.Positioner.Props,
    "side" | "align" | "sideOffset" | "collisionPadding" | "children"
  >;
}

/** Props accepted by a shared menu `Group`. */
export type MenuPartGroupProps = React.ComponentProps<typeof Menu.Group>;

/** Props accepted by a shared menu `RadioGroup`. */
export type MenuPartRadioGroupProps = React.ComponentProps<
  typeof Menu.RadioGroup
>;

/** The family of list parts `createMenuParts` binds to one `data-slot` prefix. */
export interface MenuParts {
  /** A `role="group"` wrapper that a `Label` names. */
  Group: (props: MenuPartGroupProps) => React.JSX.Element;
  /** A single-select group of radio rows. */
  RadioGroup: (props: MenuPartRadioGroupProps) => React.JSX.Element;
  /** A selectable action row. */
  Item: (props: MenuPartItemProps) => React.JSX.Element;
  /** A togglable row with a leading check indicator. */
  CheckboxItem: (props: MenuPartCheckboxItemProps) => React.JSX.Element;
  /** One option of a radio group, with a leading dot indicator. */
  RadioItem: (props: MenuPartRadioItemProps) => React.JSX.Element;
  /** A non-interactive group heading. */
  Label: (props: MenuPartLabelProps) => React.JSX.Element;
  /** A hairline divider between groups. */
  Separator: (props: MenuPartSeparatorProps) => React.JSX.Element;
  /** A trailing keyboard-shortcut hint inside a row. */
  Shortcut: (props: MenuPartShortcutProps) => React.JSX.Element;
  /** The row that opens a nested submenu, with a trailing chevron. */
  SubTrigger: (props: MenuPartSubTriggerProps) => React.JSX.Element;
}

/**
 * `createMenuParts` — binds the one menu-row implementation to a component's `data-slot` prefix.
 *
 * Base UI's `ContextMenu` namespace re-exports `Menu`'s item, checkbox-item, radio-item,
 * group-label, submenu-trigger and separator parts verbatim, so `DropdownMenu` and `ContextMenu`
 * are not "two components that look alike" — below the trigger they are the same component. This
 * factory is what makes that fact structural instead of a 200-line copy (audit B3-02).
 *
 * @example
 * const parts = createMenuParts("context-menu");
 * export const ContextMenuItem = parts.Item;
 */
export function createMenuParts(prefix: string): MenuParts {
  function Group(props: MenuPartGroupProps) {
    return <Menu.Group data-slot={`${prefix}-group`} {...props} />;
  }

  function RadioGroup(props: MenuPartRadioGroupProps) {
    return <Menu.RadioGroup data-slot={`${prefix}-radio-group`} {...props} />;
  }

  function Item({
    className,
    tone = "default",
    inset,
    ...props
  }: MenuPartItemProps) {
    return (
      <Menu.Item
        data-slot={`${prefix}-item`}
        data-tone={tone}
        data-inset={inset ? "" : undefined}
        className={cn(menuItemVariants({ tone }), className)}
        {...props}
      />
    );
  }

  function CheckboxItem({
    className,
    children,
    ...props
  }: MenuPartCheckboxItemProps) {
    return (
      <Menu.CheckboxItem
        data-slot={`${prefix}-checkbox-item`}
        className={cn(menuItemVariants({ indicator: "leading" }), className)}
        {...props}
      >
        <span className={menuIndicatorWellClassName}>
          <Menu.CheckboxItemIndicator>
            <CheckIcon className="size-(--icon-default) text-foreground" />
          </Menu.CheckboxItemIndicator>
        </span>
        {children}
      </Menu.CheckboxItem>
    );
  }

  function RadioItem({
    className,
    children,
    ...props
  }: MenuPartRadioItemProps) {
    return (
      <Menu.RadioItem
        data-slot={`${prefix}-radio-item`}
        className={cn(menuItemVariants({ indicator: "leading" }), className)}
        {...props}
      >
        <span className={menuIndicatorWellClassName}>
          <Menu.RadioItemIndicator>
            <CircleIcon className="size-2 fill-current text-foreground" />
          </Menu.RadioItemIndicator>
        </span>
        {children}
      </Menu.RadioItem>
    );
  }

  function Label({ className, inset, ...props }: MenuPartLabelProps) {
    return (
      <Menu.GroupLabel
        data-slot={`${prefix}-label`}
        data-inset={inset ? "" : undefined}
        className={cn(menuLabelClassName, className)}
        {...props}
      />
    );
  }

  function Separator({ className, ...props }: MenuPartSeparatorProps) {
    return (
      <Menu.Separator
        data-slot={`${prefix}-separator`}
        className={cn(menuSeparatorClassName, className)}
        {...props}
      />
    );
  }

  function Shortcut({ className, ...props }: MenuPartShortcutProps) {
    return (
      <span
        data-slot={`${prefix}-shortcut`}
        className={cn(menuShortcutClassName, className)}
        {...props}
      />
    );
  }

  function SubTrigger({
    className,
    inset,
    children,
    ...props
  }: MenuPartSubTriggerProps) {
    return (
      <Menu.SubmenuTrigger
        data-slot={`${prefix}-sub-trigger`}
        data-inset={inset ? "" : undefined}
        className={cn(menuItemVariants(), className)}
        {...props}
      >
        {children}
        <ChevronRightIcon className="ms-auto rtl:rotate-180" />
      </Menu.SubmenuTrigger>
    );
  }

  return {
    Group,
    RadioGroup,
    Item,
    CheckboxItem,
    RadioItem,
    Label,
    Separator,
    Shortcut,
    SubTrigger,
  };
}

/* ------------------------------------------------------------------------------------------------
 * Panel search — the ONE "search inside a panel" recipe (audit B8-04 / B9-11).
 *
 * A boxed `Input` inside a boxed popup nests two borders. The system's panel search is a full-bleed
 * header row: a leading `Search` glyph, no box of its own, and a hairline below separating it from
 * the list — the Geist/Linear/Raycast convention. Shared by Command, the Combobox popup input,
 * EmojiPicker and ShortcutOverlay.
 * ----------------------------------------------------------------------------------------------*/

/** Props accepted by `PanelSearchFrame`. */
export interface PanelSearchFrameProps extends React.ComponentProps<"div"> {
  /**
   * Tint the hairline while the field inside has focus. Turn it OFF when the field is autofocused
   * on open (a permanently-lit hairline reads as a stray border, not a focus affordance).
   * @default true
   */
  focusTint?: boolean;
  /**
   * Row height tier. `md` is the in-panel default; `lg` is the palette-in-a-dialog tier, where the
   * search row is the dialog's primary affordance.
   * @default "md"
   */
  size?: "md" | "lg";
}

/**
 * `PanelSearchFrame` — the search row's chrome: sticky header, leading glyph, hairline below.
 * Put the panel's own input inside it (Base UI's `Combobox.Input` for Command/Combobox,
 * `PanelSearchInput` everywhere else).
 *
 * @example
 * <PanelSearchFrame>
 *   <PanelSearchInput placeholder="Search…" />
 * </PanelSearchFrame>
 */
export function PanelSearchFrame({
  className,
  focusTint = true,
  size = "md",
  children,
  ...props
}: PanelSearchFrameProps) {
  return (
    <div
      data-slot="panel-search"
      className={cn(
        "sticky top-0 z-(--z-raised) flex items-center gap-2 border-b border-border bg-popover px-3",
        size === "lg" ? "h-(--size-lg)" : "h-(--size-md)",
        focusTint && "focus-within:border-ring/(--alpha-tint-border)",
        className,
      )}
      {...props}
    >
      <Search
        aria-hidden
        className={cn(
          "shrink-0 text-muted-foreground",
          size === "lg" ? "size-(--icon-action)" : "size-(--icon-default)",
        )}
      />
      {children}
    </div>
  );
}

/**
 * `panelSearchInputClassName` — the borderless, full-bleed field inside a `PanelSearchFrame`. Pass
 * it to whichever input the panel owns.
 */
export const panelSearchInputClassName = cn(
  "h-full w-full min-w-0 bg-transparent text-base text-foreground outline-none",
  "placeholder:text-muted-foreground-faint",
  "disabled:cursor-not-allowed disabled:opacity-(--opacity-dim)",
);

/** Props accepted by `PanelSearchInput`. */
export type PanelSearchInputProps = React.ComponentProps<typeof BaseInput>;

/**
 * `PanelSearchInput` — the plain search field for a panel that is not a combobox (EmojiPicker,
 * ShortcutOverlay). Comboboxes pass their own `Combobox.Input` into `PanelSearchFrame` instead,
 * because Base UI owns that element's ARIA and filtering wiring.
 *
 * @example
 * <PanelSearchFrame>
 *   <PanelSearchInput aria-label="Search emoji" placeholder="Search…" />
 * </PanelSearchFrame>
 */
export function PanelSearchInput({
  className,
  ...props
}: PanelSearchInputProps) {
  return (
    <BaseInput
      type="search"
      className={cn(panelSearchInputClassName, className)}
      {...props}
    />
  );
}

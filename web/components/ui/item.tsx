"use client";

import * as React from "react";
import { useRender } from "@base-ui/react/use-render";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@vegastack/design";
import { Separator } from "@/components/ui/separator";

/* ------------------------------------------------------------------------------------------------
 * Item — a compact row for list/feed content (a person, a file, a notification, a settings row).
 * Built on Base UI `useRender` so the whole row can become an `<a>` or `<button>` for an
 * interactive item; a plain `div` otherwise. `role="listitem"` is applied ONLY inside an
 * `ItemGroup` (which provides `role="list"` and the context that licenses it) — a standalone row
 * carries no ARIA role, so it can never raise `aria-required-parent`.
 * Every value is a semantic Tailwind token (no hardcoded colors, no raw palettes).
 * ----------------------------------------------------------------------------------------------*/

/**
 * Is this row inside an `ItemGroup`? `ItemGroup` is the only `role="list"` container in this
 * anatomy, so it is the only thing that can license a child's `role="listitem"` (ARIA
 * `aria-required-parent`). Default `false` — a standalone `Item` renders with no role.
 */
const ItemGroupContext = React.createContext(false);

export const itemVariants = cva(
  "group/item relative flex w-full flex-wrap items-center rounded-md border border-transparent text-base [&_svg]:pointer-events-none [&_svg]:shrink-0 [&:is(a,button)]:hover:bg-surface-2 [&:is(a,button)]:active:bg-surface-3",
  {
    variants: {
      variant: {
        /** No surface — blends into the parent background (default). */
        default: "bg-transparent",
        /** A hairline border around the row. */
        outline: "border-border",
        /** A filled neutral wash — reads as a self-contained block. */
        muted: "bg-surface-1",
      },
      size: {
        /** Roomy padding — the standard row density. */
        md: "gap-4 p-4",
        /** Compact padding — dense lists, sidebars. */
        sm: "gap-2.5 px-4 py-3",
      },
    },
    defaultVariants: { variant: "default", size: "md" },
  },
);

/** Surface treatment an `Item` row can take. */
export type ItemVariant = NonNullable<
  VariantProps<typeof itemVariants>["variant"]
>;
/** Padding density an `Item` row can take. */
export type ItemSize = NonNullable<VariantProps<typeof itemVariants>["size"]>;

/** Props accepted by `Item`. */
export interface ItemProps
  extends
    React.ComponentPropsWithRef<"div">,
    VariantProps<typeof itemVariants> {
  /**
   * Surface treatment.
   * - `default`: no surface, blends into the parent background.
   * - `outline`: a hairline border around the row.
   * - `muted`: a filled neutral wash.
   * @default 'default'
   */
  variant?: ItemVariant;
  /**
   * Padding density.
   * - `md`: roomy (standard row).
   * - `sm`: compact (dense lists).
   * @default 'md'
   */
  size?: ItemSize;
  /**
   * Render the row as a different element (e.g. `<a href="…" />` or `<button />`) via Base UI
   * `render` composition, making the whole row a single interactive/focusable control. Pass a
   * `ReactElement` or a render function. When set, the row keeps the composed element's native
   * `link`/`button` role instead of the default `listitem` role (see the `role` note below).

   * @default undefined
   */
  render?: useRender.RenderProp;
}

/**
 * `Item` — a compound-anatomy row: compose `ItemMedia`, `ItemContent` (with `ItemTitle` /
 * `ItemDescription`), and `ItemActions` inside it, optionally wrapped by `ItemHeader` /
 * `ItemFooter` for multi-row layouts. Group multiple rows in an `ItemGroup` (`role="list"`)
 * separated by `ItemSeparator`. `role="listitem"` is applied only when the row is inside an
 * `ItemGroup` — a `listitem` with no `list` ancestor is an axe `aria-required-parent` critical, so
 * a standalone row gets no role at all. It is also dropped when `render` composes an interactive
 * element (`<a>`/`<button>`), so its native `link`/`button` role is never clobbered. Pass an
 * explicit `role` to override either decision (it always wins).
 *
 * @example
 * <Item variant="outline">
 *   <ItemMedia variant="icon"><Mail /></ItemMedia>
 *   <ItemContent>
 *     <ItemTitle>New message</ItemTitle>
 *     <ItemDescription>Ada Lovelace sent you a message.</ItemDescription>
 *   </ItemContent>
 *   <ItemActions><Button size="sm">View</Button></ItemActions>
 * </Item>
 *
 * @example
 * // the whole row as a link
 * <Item render={<a href="/settings/billing" />}>
 *   <ItemContent><ItemTitle>Billing</ItemTitle></ItemContent>
 * </Item>
 */
export function Item({
  className,
  variant = "default",
  size = "md",
  render,
  ref,
  ...props
}: ItemProps) {
  const inGroup = React.useContext(ItemGroupContext);

  return useRender({
    render: render ?? <div />,
    defaultTagName: "div",
    ref, // forward the consumer ref onto the rendered (or composed) element
    props: {
      // `role="listitem"` is licensed by TWO conditions, both required.
      // 1. The row is inside an `ItemGroup`, which is the only thing in this file that renders
      //    `role="list"`. ARIA requires a `listitem` to have a `list` parent; a standalone Item
      //    claiming the role is an axe `aria-required-parent` CRITICAL, which is why Timeline
      //    previously had to document a `role="none"` workaround.
      // 2. The row is not `render`-composed. ARIA has no dual-role concept: forcing `listitem`
      //    onto a composed `<a>`/`<button>` would replace — not augment — that element's native
      //    `link`/`button` role, silently hiding the interactive affordance from assistive tech.
      //    Group membership is still conveyed by the surrounding `ItemGroup`.
      // An explicit `role` in `props` overrides both, because `...props` is spread last.
      ...(inGroup && !render ? { role: "listitem" } : {}),
      "data-slot": "item",
      "data-variant": variant,
      "data-size": size,
      className: cn(itemVariants({ variant, size }), className),
      ...props,
    },
  });
}

/* ------------------------------------------------------------------------------------------------
 * ItemMedia — the leading visual slot: bare content, a bordered icon chip, or a clipped image tile.
 * ----------------------------------------------------------------------------------------------*/

export const itemMediaVariants = cva(
  "flex shrink-0 items-center justify-center gap-2 [&_svg]:pointer-events-none [&_svg]:shrink-0 group-has-[[data-slot=item-description]]/item:translate-y-0.5 group-has-[[data-slot=item-description]]/item:self-start",
  {
    variants: {
      variant: {
        /** Bare — renders children as-is (e.g. an `Avatar`, a custom glyph). */
        default: "bg-transparent",
        /** A bordered, muted square chip around a `lucide-react` icon. */
        icon: "size-(--size-md) rounded-sm border border-border bg-muted [&_svg:not([class*='size-'])]:size-(--icon-default)",
        /** A clipped square tile for a thumbnail `<img>`. */
        image:
          "size-(--size-lg) overflow-hidden rounded-sm [&_img]:size-full [&_img]:object-cover",
      },
    },
    defaultVariants: { variant: "default" },
  },
);

/** Visual treatment an `ItemMedia` slot can take. */
export type ItemMediaVariant = NonNullable<
  VariantProps<typeof itemMediaVariants>["variant"]
>;

/** Props accepted by `ItemMedia`. */
export interface ItemMediaProps
  extends
    React.ComponentPropsWithRef<"div">,
    VariantProps<typeof itemMediaVariants> {
  /**
   * Visual treatment.
   * - `default`: bare children (default) — an `Avatar`, a custom glyph.
   * - `icon`: a bordered muted chip sized for a single `lucide-react` icon.
   * - `image`: a clipped square tile for a thumbnail `<img>`.
   * @default 'default'
   */
  variant?: ItemMediaVariant;
}

/**
 * `ItemMedia` — the leading visual slot of an `Item`. When the sibling `ItemContent` holds an
 * `ItemDescription`, the media nudges down and top-aligns so it sits level with the title instead
 * of the vertical center of the whole row.

 *
 * @example
 * <ItemMedia />
 */
export function ItemMedia({
  className,
  variant = "default",
  ref,
  ...props
}: ItemMediaProps) {
  return (
    <div
      ref={ref}
      data-slot="item-media"
      data-variant={variant}
      className={cn(itemMediaVariants({ variant }), className)}
      {...props}
    />
  );
}

/* ------------------------------------------------------------------------------------------------
 * ItemContent / ItemTitle / ItemDescription — the text stack. A second ItemContent (e.g. a
 * trailing timestamp column) automatically shrinks instead of sharing the flex-grow.
 * ----------------------------------------------------------------------------------------------*/

/** Props accepted by `ItemContent`. */
export type ItemContentProps = React.ComponentPropsWithRef<"div">;

/** `ItemContent` — the flexible text column of an `Item` (title + description).
 *
 * @example
 * <ItemContent />
 */
export function ItemContent({ className, ref, ...props }: ItemContentProps) {
  return (
    <div
      ref={ref}
      data-slot="item-content"
      className={cn(
        "flex min-w-0 flex-1 flex-col gap-1 [&+[data-slot=item-content]]:flex-none",
        className,
      )}
      {...props}
    />
  );
}

/** Props accepted by `ItemTitle`. */
export type ItemTitleProps = React.ComponentPropsWithRef<"div">;

/** `ItemTitle` — the primary label of an `Item` row.
 *
 * @example
 * <ItemTitle />
 */
export function ItemTitle({ className, ref, ...props }: ItemTitleProps) {
  return (
    <div
      ref={ref}
      data-slot="item-title"
      className={cn(
        // D24: the row title is the system's list-row type — `text-label` (14/500), matching
        // Sidebar menu rows, DataList cells, menu items and Message rows. The denser `size="sm"`
        // tier drops to `text-label-sm` (12/500) so a compact list keeps its 12/12 rhythm.
        "flex w-fit items-center gap-2 leading-snug text-label text-foreground",
        "group-data-[size=sm]/item:text-label-sm",
        className,
      )}
      {...props}
    />
  );
}

/** Props accepted by `ItemDescription`. */
export type ItemDescriptionProps = React.ComponentPropsWithRef<"p">;

/** `ItemDescription` — supporting body text under the `ItemTitle`. Clamps to two lines.
 *
 * @example
 * <ItemDescription />
 */
export function ItemDescription({
  className,
  ref,
  ...props
}: ItemDescriptionProps) {
  return (
    <p
      ref={ref}
      data-slot="item-description"
      className={cn(
        "line-clamp-2 text-sm leading-normal font-normal text-pretty text-muted-foreground [&>a]:underline [&>a]:underline-offset-3 [&>a:hover]:text-foreground",
        className,
      )}
      {...props}
    />
  );
}

/* ------------------------------------------------------------------------------------------------
 * ItemActions / ItemHeader / ItemFooter — layout slots for controls and multi-row compositions.
 * ----------------------------------------------------------------------------------------------*/

/** Props accepted by `ItemActions`. */
export type ItemActionsProps = React.ComponentPropsWithRef<"div">;

/** `ItemActions` — the trailing row of controls (buttons, icon-buttons, a badge) on an `Item`.
 *
 * @example
 * <ItemActions />
 */
export function ItemActions({ className, ref, ...props }: ItemActionsProps) {
  return (
    <div
      ref={ref}
      data-slot="item-actions"
      className={cn("flex items-center gap-2", className)}
      {...props}
    />
  );
}

/** Props accepted by `ItemHeader`. */
export type ItemHeaderProps = React.ComponentPropsWithRef<"div">;

/** `ItemHeader` — a full-width top row inside a multi-row `Item` (e.g. title + trailing meta).
 *
 * @example
 * <ItemHeader />
 */
export function ItemHeader({ className, ref, ...props }: ItemHeaderProps) {
  return (
    <div
      ref={ref}
      data-slot="item-header"
      className={cn(
        "flex basis-full items-center justify-between gap-2",
        className,
      )}
      {...props}
    />
  );
}

/** Props accepted by `ItemFooter`. */
export type ItemFooterProps = React.ComponentPropsWithRef<"div">;

/** `ItemFooter` — a full-width bottom row inside a multi-row `Item` (e.g. secondary actions).
 *
 * @example
 * <ItemFooter />
 */
export function ItemFooter({ className, ref, ...props }: ItemFooterProps) {
  return (
    <div
      ref={ref}
      data-slot="item-footer"
      className={cn(
        "flex basis-full items-center justify-between gap-2",
        className,
      )}
      {...props}
    />
  );
}

/* ------------------------------------------------------------------------------------------------
 * ItemGroup / ItemSeparator — a `role="list"` container of Items with a decorative divider between
 * consecutive rows. ItemSeparator wraps `Separator` decorative (the default), so it renders
 * `role="presentation"` + `aria-hidden` and never breaks the list's ARIA owned-elements contract.
 * ----------------------------------------------------------------------------------------------*/

/** Props accepted by `ItemGroup`. */
export type ItemGroupProps = React.ComponentPropsWithRef<"div">;

/** `ItemGroup` — groups `Item` rows as a semantic list (`role="list"`). It is also what licenses
 * each child `Item`'s `role="listitem"`: outside a group, an `Item` renders with no role at all.
 *
 * @example
 * <ItemGroup />
 */
export function ItemGroup({ className, ref, ...props }: ItemGroupProps) {
  return (
    <ItemGroupContext.Provider value>
      <div
        ref={ref}
        role="list"
        data-slot="item-group"
        className={cn("group/item-group flex flex-col", className)}
        {...props}
      />
    </ItemGroupContext.Provider>
  );
}

/** Props accepted by `ItemSeparator`. */
export type ItemSeparatorProps = React.ComponentPropsWithRef<typeof Separator>;

/** `ItemSeparator` — a hairline divider between rows inside an `ItemGroup`. Decorative.
 *
 * @example
 * <ItemSeparator />
 */
export function ItemSeparator({ className, ...props }: ItemSeparatorProps) {
  return (
    <Separator
      data-slot="item-separator"
      orientation="horizontal"
      className={cn("my-0", className)}
      {...props}
    />
  );
}

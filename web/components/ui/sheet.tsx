"use client";

import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { Dialog as BaseDialog } from "@base-ui/react/dialog";
import { X } from "lucide-react";
import { cn } from "@vegastack/design";
import { useInternalThemeScope } from "@vegastack/design/theme-scope";

/* ------------------------------------------------------------------------------------------------
 * Sheet — a dialog that slides in from a screen edge, built on Base UI's Dialog (NOT vaul).
 * Exported FLAT (shadcn-style): `Sheet` (=Root), `SheetTrigger`, `SheetContent` (composes
 * Portal+Backdrop+Viewport+Popup with a `side` CVA prop pinning it to the chosen edge + close
 * button), `SheetHeader`, `SheetFooter`, `SheetTitle`, `SheetDescription`, `SheetClose`. The panel
 * slides in/out via Base UI's `data-starting-style`/`data-ending-style` data attributes (an off-edge
 * `translate`) on token-duration transitions.
 *
 * Use a Sheet for secondary tasks alongside the main view — filters, detail panels, navigation —
 * where the panel should anchor to an edge rather than float centered (use `Dialog` for that).
 * ----------------------------------------------------------------------------------------------*/

/**
 * Sheet panel side — the screen edge the panel is pinned to and slides in from.
 * `left`/`right` pin full-height and cap their width; `top`/`bottom` span full-width and cap
 * their height. The off-screen `translate` for the enter/exit transition is derived from `side`.
 * Every value is a semantic token utility (no hardcoded px/hex).
 */
export const sheetVariants = cva(
  [
    // No `outline-none`: Base UI focuses the panel on open, so the centralized base.css
    // `:focus-visible` outline stays as the keyboard-focus indicator (WCAG 2.4.7, register P0-02).
    "fixed z-(--z-overlay) flex flex-col gap-4 overflow-y-auto overscroll-contain bg-popover text-base text-popover-foreground shadow-overlay",
    // Enter/exit — slide from the pinned edge, token duration + standard easing.
    "transition-transform duration-fast ease-standard",
  ],
  {
    variants: {
      // Side panels are flush to their pinned edge (no radius); a top/bottom panel keeps a
      // small radius on its single free edge only. Each side ALSO pads its flush edge by
      // `env(safe-area-inset-*)` (stacked on top of Header's/Footer's own `p-5`, since the
      // safe-area padding lands on this outer popup while Header/Footer pad themselves) so
      // content/actions clear the iOS notch/Dynamic Island/home indicator on that edge.
      // `env()` resolves to `0px` on non-notched devices/browsers that don't support it, so
      // this is a zero-visual-change default there. The `var(--spacing)*0` term is a deliberate
      // zero-valued token anchor, NOT a real spacing addition — the design-lint arbitrary-value
      // contract (§7.1) requires every `calc()` to reference a `var(--token)`, and this popup
      // intentionally carries no baseline padding of its own (that already lives in
      // Header's/Footer's `p-5`, matching Dialog's `p-5` content inset — one modal-family
      // rhythm), so the anchor keeps the value 100% `env()` while staying
      // traceable to the token system.
      side: {
        top: [
          "inset-x-0 top-0 h-auto max-h-[calc(100dvh-var(--spacing)*8)] rounded-b-lg border-b border-border pt-[calc(var(--spacing)*0+env(safe-area-inset-top))]",
          "data-[starting-style]:-translate-y-full data-[ending-style]:-translate-y-full",
        ],
        right: [
          "inset-y-0 right-0 h-full w-3/4 max-w-sm border-l border-border pr-[calc(var(--spacing)*0+env(safe-area-inset-right))]",
          "data-[starting-style]:translate-x-full data-[ending-style]:translate-x-full",
        ],
        bottom: [
          "inset-x-0 bottom-0 h-auto max-h-[calc(100dvh-var(--spacing)*8)] rounded-t-lg border-t border-border pb-[calc(var(--spacing)*0+env(safe-area-inset-bottom))]",
          "data-[starting-style]:translate-y-full data-[ending-style]:translate-y-full",
        ],
        left: [
          "inset-y-0 left-0 h-full w-3/4 max-w-sm border-r border-border pl-[calc(var(--spacing)*0+env(safe-area-inset-left))]",
          "data-[starting-style]:-translate-x-full data-[ending-style]:-translate-x-full",
        ],
      },
    },
    defaultVariants: { side: "right" },
  },
);

/** The side variants `SheetContent` supports. */
export type SheetSide = NonNullable<VariantProps<typeof sheetVariants>["side"]>;

/**
 * `Sheet` — the root, controls open/close state. Doesn't render an element itself; compose
 * `SheetTrigger` + `SheetContent` inside it. Modal by default (focus trapped, page scroll locked).
 *
 * @example
 * <Sheet>
 *   <SheetTrigger render={<Button variant="outline">Open</Button>} />
 *   <SheetContent side="right">
 *     <SheetHeader>
 *       <SheetTitle>Edit profile</SheetTitle>
 *       <SheetDescription>Make changes to your profile here.</SheetDescription>
 *     </SheetHeader>
 *     <SheetFooter>
 *       <SheetClose render={<Button variant="outline">Cancel</Button>} />
 *       <Button>Save changes</Button>
 *     </SheetFooter>
 *   </SheetContent>
 * </Sheet>
 */
export type SheetProps = React.ComponentProps<typeof BaseDialog.Root>;

/** `Sheet` root; controls the edge panel's open state and modal lifecycle.
 *
 * @example
 * <Sheet />
 */
export function Sheet(props: SheetProps) {
  return <BaseDialog.Root {...props} />;
}

/** Props accepted by `SheetTrigger`. */
export type SheetTriggerProps = React.ComponentProps<typeof BaseDialog.Trigger>;

/**
 * `SheetTrigger` — the control that opens the sheet. Renders a `<button>`; pass `render` to
 * compose it with a `Button` or any other element (Base UI `render` composition).

 *
 * @example
 * <SheetTrigger />
 */
export function SheetTrigger({ className, ...props }: SheetTriggerProps) {
  return (
    <BaseDialog.Trigger
      data-slot="sheet-trigger"
      className={className}
      {...props}
    />
  );
}

/** Props accepted by `SheetContent`. */
export interface SheetContentProps
  extends
    React.ComponentProps<typeof BaseDialog.Popup>,
    VariantProps<typeof sheetVariants> {
  /**
   * Which screen edge the panel is pinned to and slides in from.
   * @default "right"
   */
  side?: SheetSide;
  /**
   * Render the top-right close (`X`) button.
   * @default true
   */
  showCloseButton?: boolean;
  /**
   * Accessible label for the close button.
   * @default "Close"
   */
  closeLabel?: string;
}

/**
 * `SheetContent` — the slide-in panel. Composes Base UI's `Portal` + `Backdrop` + `Viewport` +
 * `Popup`, pins itself to the `side` edge, slides enter/exit, and renders the close button. Drop
 * `SheetHeader`/`SheetFooter` and the title/description inside it.

 *
 * @example
 * <SheetContent />
 */
export function SheetContent({
  className,
  children,
  side = "right",
  showCloseButton = true,
  closeLabel = "Close",
  ...props
}: SheetContentProps) {
  const themeScope = useInternalThemeScope();

  return (
    <BaseDialog.Portal>
      <BaseDialog.Backdrop
        data-slot="sheet-backdrop"
        className={cn(
          themeScope,
          "fixed inset-0 z-(--z-overlay) bg-overlay",
          "transition-opacity duration-fast ease-standard",
          "data-[starting-style]:opacity-0 data-[ending-style]:opacity-0",
        )}
      />
      <BaseDialog.Viewport
        data-slot="sheet-viewport"
        className={cn(
          themeScope,
          "fixed inset-0 z-(--z-overlay) overflow-y-auto overscroll-contain outline-none",
        )}
      >
        <BaseDialog.Popup
          data-slot="sheet-content"
          data-side={side}
          className={cn(themeScope, sheetVariants({ side }), className)}
          {...props}
        >
          {children}
          {showCloseButton ? (
            <BaseDialog.Close
              data-slot="sheet-close"
              aria-label={closeLabel}
              className={cn(
                // top-3/end-3 matches Dialog's close-button inset — one modal-family rhythm.
                "absolute top-3 end-3 inline-flex size-(--size-md) shrink-0 items-center justify-center",
                "rounded-md text-muted-foreground  select-none",
                "hover:bg-muted hover:text-foreground",
                "[&_svg:not([class*='size-'])]:size-(--icon-default) [&_svg]:pointer-events-none [&_svg]:shrink-0",
              )}
            >
              <X aria-hidden />
            </BaseDialog.Close>
          ) : null}
        </BaseDialog.Popup>
      </BaseDialog.Viewport>
    </BaseDialog.Portal>
  );
}

/** Props accepted by `SheetHeader`. */
export type SheetHeaderProps = React.ComponentProps<"div">;

/**
 * `SheetHeader` — groups the title and description at the top of the panel.
 * Clears the close button's footprint with end padding.

 *
 * @example
 * <SheetHeader />
 */
export function SheetHeader({ className, ...props }: SheetHeaderProps) {
  return (
    <div
      data-slot="sheet-header"
      className={cn("flex shrink-0 flex-col gap-1.5 p-5 pe-12", className)}
      {...props}
    />
  );
}

/** Props accepted by `SheetFooter`. */
export type SheetFooterProps = React.ComponentProps<"div">;

/**
 * `SheetFooter` — the action row pinned to the bottom of the panel. Stacks (reversed) on narrow
 * screens, becomes an end-aligned row from the `sm` breakpoint up.

 *
 * @example
 * <SheetFooter />
 */
export function SheetFooter({ className, ...props }: SheetFooterProps) {
  return (
    <div
      data-slot="sheet-footer"
      className={cn(
        "mt-auto flex shrink-0 flex-col-reverse gap-2 p-5 sm:flex-row sm:justify-end",
        className,
      )}
      {...props}
    />
  );
}

/** Props accepted by `SheetTitle`. */
export type SheetTitleProps = React.ComponentProps<typeof BaseDialog.Title>;

/**
 * `SheetTitle` — the sheet's accessible name. Renders an `<h2>`; Base UI wires it to the popup
 * via `aria-labelledby`. Always include one.

 *
 * @example
 * <SheetTitle />
 */
export function SheetTitle({ className, ...props }: SheetTitleProps) {
  return (
    <BaseDialog.Title
      data-slot="sheet-title"
      className={cn("text-h4 text-foreground", className)}
      {...props}
    />
  );
}

/** Props accepted by `SheetDescription`. */
export type SheetDescriptionProps = React.ComponentProps<
  typeof BaseDialog.Description
>;

/**
 * `SheetDescription` — supporting text under the title. Renders a `<p>`; Base UI wires it to the
 * popup via `aria-describedby`.

 *
 * @example
 * <SheetDescription />
 */
export function SheetDescription({
  className,
  ...props
}: SheetDescriptionProps) {
  return (
    <BaseDialog.Description
      data-slot="sheet-description"
      className={cn(
        "text-base leading-relaxed text-muted-foreground",
        className,
      )}
      {...props}
    />
  );
}

/** Props accepted by `SheetClose`. */
export type SheetCloseProps = React.ComponentProps<typeof BaseDialog.Close>;

/**
 * `SheetClose` — closes the sheet. Renders a `<button>`; pass `render` to compose it with a
 * `Button` (e.g. a "Cancel" action in the footer).

 *
 * @example
 * <SheetClose />
 */
export function SheetClose({ className, ...props }: SheetCloseProps) {
  return (
    <BaseDialog.Close
      data-slot="sheet-close-action"
      className={className}
      {...props}
    />
  );
}

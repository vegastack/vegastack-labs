"use client";

import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { Drawer } from "@base-ui/react/drawer";
import { X } from "lucide-react";
import { cn } from "@vegastack/design";
import { useInternalThemeScope } from "@vegastack/design/theme-scope";
import { IconButton } from "@/components/ui/icon-button";
import { useModalInert } from "@/components/ui/use-modal-inert";

/* ------------------------------------------------------------------------------------------------
 * Sheet — a panel that slides in from a screen edge, built on Base UI's `Drawer` (audit D15).
 *
 * It used to be a positioned `Dialog`. Base UI's own guidance is the reason it no longer is:
 * "Drawer extends Dialog: it adds gesture support, snap points, and indent effects. If you don't
 * need these, use Dialog instead." A Sheet is exactly the surface that needs them — swipe-to-
 * dismiss, snap points for a bottom sheet, and software-keyboard handling for a sheet that contains
 * form fields. Everything the old build hand-rolled (the off-edge `translate` pair, the edge
 * pinning) is still ours; the gesture layer is now Base UI's.
 *
 * TWO API CHANGES came with the move, both deliberate and both breaking:
 * - `side` moved from `SheetContent` to `Sheet` (the root). The edge decides the dismiss gesture,
 *   and Base UI reads `swipeDirection` on the root — a `side` that lived on the content could
 *   disagree with the gesture, which is not a state worth being able to express.
 * - `SheetContent` gained `size` (`sm | md | lg | full`), so consumers stop overriding the panel's
 *   dimensions through `className` (audit B3-11).
 * ----------------------------------------------------------------------------------------------*/

/** The screen edge a sheet is pinned to and slides in from. */
export type SheetSide = "top" | "right" | "bottom" | "left";

/** The panel's extent along its free axis: width for a side sheet, height for a top/bottom one. */
export type SheetSize = "sm" | "md" | "lg" | "full";

// The edge is a root concern (it picks the dismiss gesture) but the content paints it, so it
// travels by context rather than being restated on both parts.
const SheetSideContext = React.createContext<SheetSide>("right");
const SheetNativeInertContext = React.createContext(true);

const SWIPE_DIRECTION = {
  top: "up",
  right: "right",
  bottom: "down",
  left: "left",
} as const satisfies Record<SheetSide, Drawer.Root.Props["swipeDirection"]>;

/**
 * The panel surface: pinned to its edge, sized by `size`, and translated off-edge while entering,
 * leaving, or being dragged.
 *
 * Each side pads its flush edge by `env(safe-area-inset-*)` so content clears the iOS notch /
 * Dynamic Island / home indicator on that edge. `env()` resolves to `0px` where it is unsupported,
 * so this is a zero-visual-change default elsewhere. The `var(--spacing)*0` term is a deliberate
 * zero-valued token anchor, NOT a spacing addition — design-lint's arbitrary-value contract (§7.1)
 * requires every `calc()` to reference a `var(--token)`, and the popup intentionally carries no
 * baseline padding of its own (that lives in Header's/Footer's `p-6`, the D14 modal-family tier).
 *
 * The swipe offset is `--drawer-swipe-movement-*`, published by Base UI while a drag is in
 * progress; `data-swiping` drops the transition so the panel tracks the finger exactly.
 */
export const sheetVariants = cva(
  [
    // No `outline-none`: Base UI focuses the panel on open, so the centralized base.css
    // `:focus-visible` outline stays as the keyboard-focus indicator (WCAG 2.4.7, register P0-02).
    // `z-(--z-overlay)` is load-bearing, not decoration: the Sheet popup is a portalled overlay
    // and must sit in the overlay band. Base UI's Drawer popup, unlike the Dialog popup this
    // replaced, does NOT carry a z-index of its own, so dropping it let a sheet render beneath
    // other overlay-band content (caught by test/overlay-portal.browser.test.tsx).
    "relative z-(--z-overlay) flex flex-col gap-4 overflow-y-auto overscroll-contain bg-popover text-base text-popover-foreground shadow-overlay",
    // D11: a modal-family surface moves at `base` (200ms), not the floating tier's 150ms.
    "transition-transform duration-base ease-standard data-[swiping]:duration-0",
  ],
  {
    variants: {
      // Side panels are flush to their pinned edge (no radius); a top/bottom panel keeps a small
      // radius on its single free edge only.
      side: {
        top: [
          "w-full rounded-b-lg border-b border-border pt-[calc(var(--spacing)*0+env(safe-area-inset-top))]",
          "translate-y-(--drawer-swipe-movement-y)",
          "data-[starting-style]:-translate-y-full data-[ending-style]:-translate-y-full",
        ].join(" "),
        right: [
          "h-full border-l border-border pr-[calc(var(--spacing)*0+env(safe-area-inset-right))]",
          "translate-x-(--drawer-swipe-movement-x)",
          "data-[starting-style]:translate-x-full data-[ending-style]:translate-x-full",
        ].join(" "),
        bottom: [
          "w-full rounded-t-lg border-t border-border pb-[calc(var(--spacing)*0+env(safe-area-inset-bottom))]",
          "translate-y-(--drawer-swipe-movement-y)",
          "data-[starting-style]:translate-y-full data-[ending-style]:translate-y-full",
        ].join(" "),
        left: [
          "h-full border-r border-border pl-[calc(var(--spacing)*0+env(safe-area-inset-left))]",
          "translate-x-(--drawer-swipe-movement-x)",
          "data-[starting-style]:-translate-x-full data-[ending-style]:-translate-x-full",
        ].join(" "),
      },
      /**
       * One panel-size vocabulary in both axes: a left/right sheet reads the tier as a width, a
       * top/bottom sheet as a height, so `md` is the same 18rem panel either way.
       */
      size: { sm: "", md: "", lg: "", full: "" },
    },
    compoundVariants: [
      ...(["left", "right"] as const).flatMap((side) => [
        {
          side,
          size: "sm" as const,
          class: "w-(--panel-width-sm) max-w-[calc(100vw-var(--spacing)*8)]",
        },
        {
          side,
          size: "md" as const,
          class: "w-(--panel-width-md) max-w-[calc(100vw-var(--spacing)*8)]",
        },
        {
          side,
          size: "lg" as const,
          class: "w-(--panel-width-lg) max-w-[calc(100vw-var(--spacing)*8)]",
        },
        { side, size: "full" as const, class: "w-full" },
      ]),
      ...(["top", "bottom"] as const).flatMap((side) => [
        { side, size: "sm" as const, class: "max-h-(--panel-width-sm)" },
        { side, size: "md" as const, class: "max-h-(--panel-width-md)" },
        { side, size: "lg" as const, class: "max-h-(--panel-width-lg)" },
        { side, size: "full" as const, class: "max-h-full" },
      ]),
    ],
    defaultVariants: { side: "right", size: "md" },
  },
);

// Where the panel sits inside the full-viewport drawer viewport.
const VIEWPORT_ALIGNMENT: Record<SheetSide, string> = {
  top: "items-start justify-center",
  right: "items-stretch justify-end",
  bottom: "items-end justify-center",
  left: "items-stretch justify-start",
};

/** Props accepted by `Sheet`. */
export interface SheetProps extends Omit<Drawer.Root.Props, "swipeDirection"> {
  /**
   * Which screen edge the panel is pinned to, slides in from, and is swiped towards to dismiss.
   * @default "right"
   */
  side?: SheetSide;
}

/**
 * `Sheet` — the root, controls open/close state. Doesn't render an element itself; compose
 * `SheetTrigger` + `SheetContent` inside it. Modal by default (focus trapped, page scroll locked),
 * dismissable by Escape, backdrop press, or a swipe towards `side`. Base UI's `Drawer` props pass
 * straight through, so `snapPoints` / `snapPoint` / `onSnapPointChange` work on a bottom sheet with
 * no extra wiring.
 *
 * @example
 * <Sheet side="right">
 *   <SheetTrigger render={<Button variant="outline">Open</Button>} />
 *   <SheetContent size="md">
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
export function Sheet({ side = "right", modal, ...props }: SheetProps) {
  const nativeInert = modal === undefined || modal === true;
  // The provider wraps the root rather than its children so `children` reaches Base UI untouched —
  // `Drawer.Root` also accepts a payload render function for detached triggers.
  return (
    <SheetNativeInertContext.Provider value={nativeInert}>
      <SheetSideContext.Provider value={side}>
        <Drawer.Root
          modal={modal}
          swipeDirection={SWIPE_DIRECTION[side]}
          {...props}
        />
      </SheetSideContext.Provider>
    </SheetNativeInertContext.Provider>
  );
}

/** Props accepted by `SheetProvider`. */
export type SheetProviderProps = Drawer.Provider.Props;

/**
 * `SheetProvider` — groups sibling sheets so nested/stacked panels animate as one stack. Mount it
 * around a region that opens several sheets; a single sheet does not need it.
 *
 * @example
 * <SheetProvider>{children}</SheetProvider>
 */
export const SheetProvider = Drawer.Provider;

/** Props accepted by `SheetVirtualKeyboardProvider`. */
export type SheetVirtualKeyboardProviderProps =
  Drawer.VirtualKeyboardProvider.Props;

/**
 * `SheetVirtualKeyboardProvider` — opt a bottom sheet that contains form fields into Base UI's
 * software-keyboard handling (keyboard-aware focus and scrolling). Sheets without it are
 * unaffected.
 *
 * @example
 * <SheetVirtualKeyboardProvider>
 *   <Sheet side="bottom">…</Sheet>
 * </SheetVirtualKeyboardProvider>
 */
export const SheetVirtualKeyboardProvider = Drawer.VirtualKeyboardProvider;

/** Props accepted by `SheetTrigger`. */
export type SheetTriggerProps = Drawer.Trigger.Props;

/**
 * `SheetTrigger` — the control that opens the sheet. Renders a `<button>`; pass `render` to compose
 * it with a `Button` or any other element (Base UI `render` composition).
 *
 * @example
 * <SheetTrigger />
 */
export function SheetTrigger({ className, ...props }: SheetTriggerProps) {
  return (
    <Drawer.Trigger
      data-slot="sheet-trigger"
      className={className}
      {...props}
    />
  );
}

/** Props accepted by `SheetContent`. */
export interface SheetContentProps
  extends Drawer.Popup.Props, Pick<VariantProps<typeof sheetVariants>, "size"> {
  /**
   * The panel's extent along its free axis — width for a `left`/`right` sheet, height for a
   * `top`/`bottom` one. `full` spans the viewport.
   * @default "md"
   */
  size?: SheetSize;
  /**
   * Render the top-end close (`X`) button.
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
 * `SheetContent` — the slide-in panel. Composes Base UI Drawer's `Portal` + `Backdrop` +
 * `Viewport` + `Popup` + `Content`, pins itself to the root's `side`, sizes itself with `size`, and
 * renders the close button. Drop `SheetHeader`/`SheetFooter` and the title/description inside it.
 *
 * @example
 * <SheetContent size="lg" />
 */
export function SheetContent({
  className,
  children,
  size = "md",
  showCloseButton = true,
  closeLabel = "Close",
  ref,
  ...props
}: SheetContentProps) {
  const themeScope = useInternalThemeScope();
  const side = React.useContext(SheetSideContext);
  const nativeInert = React.useContext(SheetNativeInertContext);
  const mergedRef = useModalInert<HTMLDivElement>({
    ref,
    enabled: nativeInert,
  });

  return (
    <Drawer.Portal>
      <Drawer.Backdrop
        data-slot="sheet-backdrop"
        className={cn(
          themeScope,
          "fixed inset-0 z-(--z-overlay) bg-overlay",
          "transition-opacity duration-base ease-standard data-[swiping]:duration-0",
          "data-[starting-style]:opacity-0 data-[ending-style]:opacity-0",
        )}
      />
      <Drawer.Viewport
        data-slot="sheet-viewport"
        className={cn(
          themeScope,
          "fixed inset-0 z-(--z-overlay) flex",
          VIEWPORT_ALIGNMENT[side],
        )}
      >
        <Drawer.Popup
          ref={mergedRef}
          data-slot="sheet-content"
          data-side={side}
          data-size={size}
          className={cn(themeScope, sheetVariants({ side, size }), className)}
          {...props}
        >
          {/* `Drawer.Content` is what lets a mouse pointer select text inside the panel without
              the selection being read as a swipe. */}
          <Drawer.Content
            data-slot="sheet-body"
            className="flex min-h-0 flex-1 flex-col gap-4"
          >
            {children}
          </Drawer.Content>
          {showCloseButton ? (
            <Drawer.Close
              render={
                <IconButton
                  variant="ghost"
                  size="md"
                  data-slot="sheet-close"
                  aria-label={closeLabel}
                  // top-3/end-3 matches Dialog's close-button inset — one modal-family rhythm.
                  className="absolute top-3 end-3 text-muted-foreground"
                />
              }
            >
              <X aria-hidden />
            </Drawer.Close>
          ) : null}
        </Drawer.Popup>
      </Drawer.Viewport>
    </Drawer.Portal>
  );
}

/** Props accepted by `SheetHeader`. */
export type SheetHeaderProps = React.ComponentProps<"div">;

/**
 * `SheetHeader` — groups the title and description at the top of the panel. Clears the close
 * button's footprint with end padding, and takes the 24px modal-family padding tier (D14) — the
 * same value `DialogHeader` uses.
 *
 * @example
 * <SheetHeader />
 */
export function SheetHeader({ className, ...props }: SheetHeaderProps) {
  return (
    <div
      data-slot="sheet-header"
      className={cn("flex shrink-0 flex-col gap-1.5 p-6 pe-10", className)}
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
        "mt-auto flex shrink-0 flex-col-reverse gap-2 p-6 sm:flex-row sm:justify-end",
        className,
      )}
      {...props}
    />
  );
}

/** Props accepted by `SheetTitle`. */
export type SheetTitleProps = Drawer.Title.Props;

/**
 * `SheetTitle` — the sheet's accessible name. Renders an `<h2>`; Base UI wires it to the popup via
 * `aria-labelledby`. Always include one.
 *
 * @example
 * <SheetTitle />
 */
export function SheetTitle({ className, ...props }: SheetTitleProps) {
  return (
    <Drawer.Title
      data-slot="sheet-title"
      className={cn("text-h4 text-foreground", className)}
      {...props}
    />
  );
}

/** Props accepted by `SheetDescription`. */
export type SheetDescriptionProps = Drawer.Description.Props;

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
    <Drawer.Description
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
export type SheetCloseProps = Drawer.Close.Props;

/**
 * `SheetClose` — closes the sheet. Renders a `<button>`; pass `render` to compose it with a
 * `Button` (e.g. a "Cancel" action in the footer).
 *
 * @example
 * <SheetClose />
 */
export function SheetClose({ className, ...props }: SheetCloseProps) {
  return (
    <Drawer.Close
      data-slot="sheet-close-action"
      className={className}
      {...props}
    />
  );
}

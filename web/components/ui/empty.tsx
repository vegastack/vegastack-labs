import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@vegastack/design";

/**
 * Empty root variants — `size` (vertical density) × `bordered` (dashed
 * outline) × `surface` (card vs. transparent background). Every value is a
 * semantic Tailwind token (no hardcoded colors, no inline styles).
 */
export const emptyVariants = cva(
  "flex min-w-0 flex-col items-center justify-center gap-4 rounded-lg p-6 text-center text-balance",
  {
    variants: {
      size: {
        sm: "py-8",
        default: "py-12",
        lg: "py-16",
      },
      bordered: {
        true: "border border-dashed border-border",
        false: "",
      },
      surface: {
        // A border (borders-only canon — no shadows) keeps the block self-contained
        // even on card-colored canvases where `bg-card` alone is invisible. Combined
        // with `bordered` (dashed), the dashed style wins via tw-merge.
        card: "border border-border bg-card",
        transparent: "bg-transparent",
      },
    },
    defaultVariants: {
      size: "default",
      bordered: false,
      surface: "transparent",
    },
  },
);

/**
 * Media variants — `variant` follows the shadcn Empty anatomy (`default` bare /
 * `icon` chip) and `intent` drives the tinted chip color. `default` renders
 * children as-is (an illustration, an avatar); `icon` wraps a `lucide-react`
 * icon in a tinted circular chip at the `--icon-feature` size.
 */
export const emptyMediaVariants = cva(
  "flex shrink-0 items-center justify-center [&_svg]:pointer-events-none [&_svg]:shrink-0",
  {
    variants: {
      variant: {
        default: "bg-transparent",
        icon: "rounded-full p-3 [&_svg:not([class*='size-'])]:size-(--icon-feature)",
      },
      intent: {
        default: "",
        info: "",
        destructive: "",
      },
    },
    compoundVariants: [
      {
        variant: "icon",
        intent: "default",
        class: "bg-muted text-muted-foreground",
      },
      {
        variant: "icon",
        intent: "info",
        class: "bg-info-subtle text-info-text",
      },
      {
        variant: "icon",
        intent: "destructive",
        class: "bg-destructive-subtle text-destructive-text",
      },
    ],
    defaultVariants: { variant: "icon", intent: "default" },
  },
);

/** The intent tints the icon chip supports. */
export type EmptyIntent = NonNullable<
  VariantProps<typeof emptyMediaVariants>["intent"]
>;

/** Props accepted by `Empty`. */
export interface EmptyProps
  extends
    React.ComponentPropsWithRef<"div">,
    VariantProps<typeof emptyVariants> {
  /**
   * Vertical density — `sm` for inside cards, `default` standalone, `lg` for
   * full-page empties.
   * @default "default"
   */
  size?: VariantProps<typeof emptyVariants>["size"];
  /**
   * Draw a dashed border around the container (the classic "drop zone" look).
   * @default false
   */
  bordered?: boolean;
  /**
   * Background surface — `card` for a filled panel, `transparent` to inherit the
   * parent surface.
   * @default "transparent"
   */
  surface?: VariantProps<typeof emptyVariants>["surface"];
}

/**
 * `Empty` — a presentational container shown when a list, table, or panel has
 * no content. Follows the shadcn Empty anatomy: compose `EmptyHeader`
 * (wrapping `EmptyMedia`, `EmptyTitle`, `EmptyDescription`) and `EmptyContent`
 * (call-to-action row). Server-safe (no hooks / no `'use client'`).
 *
 * @example
 * <Empty bordered>
 *   <EmptyHeader>
 *     <EmptyMedia variant="icon">
 *       <Inbox />
 *     </EmptyMedia>
 *     <EmptyTitle>No messages</EmptyTitle>
 *     <EmptyDescription>Your inbox is empty.</EmptyDescription>
 *   </EmptyHeader>
 *   <EmptyContent>
 *     <Button>Compose</Button>
 *   </EmptyContent>
 * </Empty>
 */
function Empty({
  className,
  size = "default",
  bordered = false,
  surface = "transparent",
  ...props
}: EmptyProps) {
  return (
    <div
      data-slot="empty"
      data-bordered={bordered ? "" : undefined}
      data-surface={surface}
      className={cn(emptyVariants({ size, bordered, surface }), className)}
      {...props}
    />
  );
}

/** Props accepted by `EmptyHeader`. */
export type EmptyHeaderProps = React.ComponentPropsWithRef<"div">;

/**
 * `EmptyHeader` — groups the media, title, and description with tight spacing
 * (shadcn Empty anatomy).

 *
 * @example
 * <EmptyHeader />
 */
function EmptyHeader({ className, ...props }: EmptyHeaderProps) {
  return (
    <div
      data-slot="empty-header"
      className={cn(
        "flex max-w-sm flex-col items-center gap-2 text-center",
        className,
      )}
      {...props}
    />
  );
}

/** Props accepted by `EmptyMedia`. */
export interface EmptyMediaProps
  extends
    React.ComponentPropsWithRef<"div">,
    VariantProps<typeof emptyMediaVariants> {
  /**
   * `icon` wraps children in the tinted circular chip; `default` renders them
   * bare (illustration, avatar, screenshot).
   * @default "icon"
   */
  variant?: VariantProps<typeof emptyMediaVariants>["variant"];
  /**
   * Color intent of the icon chip — neutral `default`, `info`, or `destructive`.
   * @default "default"
   */
  intent?: EmptyIntent;
}

/**
 * `EmptyMedia` — the visual slot above the title: a tinted icon chip
 * (`variant="icon"`) or bare media (`variant="default"`). Decorative by
 * default; the title carries the meaning.

 *
 * @example
 * <EmptyMedia />
 */
function EmptyMedia({
  className,
  variant = "icon",
  intent = "default",
  children,
  ...props
}: EmptyMediaProps) {
  return (
    <div
      data-slot="empty-media"
      data-variant={variant}
      data-intent={intent}
      aria-hidden
      className={cn(emptyMediaVariants({ variant, intent }), className)}
      {...props}
    >
      {children}
    </div>
  );
}

/** Props accepted by `EmptyTitle`. */
export type EmptyTitleProps = React.ComponentPropsWithRef<"h3">;

/** `EmptyTitle` — the primary heading of the empty state.
 *
 * @example
 * <EmptyTitle />
 */
function EmptyTitle({ className, ...props }: EmptyTitleProps) {
  return (
    <h3
      data-slot="empty-title"
      className={cn("text-base font-medium text-foreground", className)}
      {...props}
    />
  );
}

/** Props accepted by `EmptyDescription`. */
export type EmptyDescriptionProps = React.ComponentPropsWithRef<"p">;

/** `EmptyDescription` — supporting body text under the title.
 *
 * @example
 * <EmptyDescription />
 */
function EmptyDescription({ className, ...props }: EmptyDescriptionProps) {
  return (
    <p
      data-slot="empty-description"
      className={cn(
        "max-w-sm text-sm leading-normal text-muted-foreground",
        className,
      )}
      {...props}
    />
  );
}

/** Props accepted by `EmptyContent`. */
export type EmptyContentProps = React.ComponentPropsWithRef<"div">;

/** `EmptyContent` — a centered row of call-to-action controls.
 *
 * @example
 * <EmptyContent />
 */
function EmptyContent({ className, ...props }: EmptyContentProps) {
  return (
    <div
      data-slot="empty-content"
      className={cn(
        "mt-2 flex flex-wrap items-center justify-center gap-2",
        className,
      )}
      {...props}
    />
  );
}

/* ------------------------------------------------------------------------------------------------
 * EmptyIllustration — the monoline drawing tier (Wave 2, from the app-teardown empty-state
 * system): six built-in currentColor line drawings on a faint grid-paper ground, so every
 * surface's empty state shares one drawing language in both themes. Decorative (aria-hidden);
 * the EmptyTitle carries the meaning. Color rides the text color — the default muted ink, or
 * `text-destructive-text` for the blocked/error tier ("configure a mailbox first"-class states).
 * All geometry is simple strokes (rects/circles/lines) — no hand-authored path soup.
 * ----------------------------------------------------------------------------------------------*/

/** The built-in monoline drawings. */
export type EmptyIllustrationName =
  | "clipboard" // page-level "no items yet"
  | "bell" // notifications / activity
  | "search" // no results for a query
  | "box" // generic collection / archive
  | "error" // blocked / failed states (pair with text-destructive-text)
  | "not-found"; // 404-class "this thing does not exist"

/** Props accepted by `EmptyIllustration`. */
export interface EmptyIllustrationProps extends React.ComponentPropsWithRef<"svg"> {
  /** Which drawing to render. */
  name: EmptyIllustrationName;
}

/** Faint grid-paper ground shared by every drawing (opacity via the track token). */
function IllustrationGround() {
  return (
    <g
      className="opacity-(--opacity-track)"
      stroke="currentColor"
      strokeWidth="1"
    >
      <line x1="24" y1="8" x2="24" y2="88" />
      <line x1="72" y1="8" x2="72" y2="88" />
      <line x1="8" y1="24" x2="88" y2="24" />
      <line x1="8" y1="72" x2="88" y2="72" />
    </g>
  );
}

const ILLUSTRATIONS: Record<EmptyIllustrationName, React.ReactNode> = {
  clipboard: (
    <g>
      <rect x="32" y="22" width="32" height="52" rx="4" />
      <rect x="41" y="17" width="14" height="9" rx="2" />
      <line x1="39" y1="36" x2="57" y2="36" />
      <line x1="39" y1="45" x2="57" y2="45" />
      <line x1="39" y1="54" x2="50" y2="54" />
    </g>
  ),
  bell: (
    <g>
      <path d="M48 24c-9 0-15 7-15 16v10l-5 8h40l-5-8V40c0-9-6-16-15-16Z" />
      <path d="M43 60a5 5 0 0 0 10 0" />
      <line x1="48" y1="18" x2="48" y2="24" />
    </g>
  ),
  search: (
    <g>
      <rect x="30" y="42" width="36" height="26" rx="3" />
      <path d="M30 50l18 8 18-8" />
      <circle cx="58" cy="32" r="9" />
      <line x1="64.5" y1="38.5" x2="71" y2="45" />
    </g>
  ),
  box: (
    <g>
      <path d="M30 40l18-9 18 9v22l-18 9-18-9V40Z" />
      <path d="M30 40l18 9 18-9" />
      <line x1="48" y1="49" x2="48" y2="71" />
    </g>
  ),
  error: (
    <g>
      <rect x="30" y="34" width="36" height="26" rx="3" />
      <path d="M30 38l18 12 18-12" />
      <line x1="38" y1="66" x2="58" y2="66" />
    </g>
  ),
  "not-found": (
    <g>
      <path d="M32 42l14-7 14 7v16l-14 7-14-7V42Z" />
      <path d="M32 42l14 7 14-7" />
      <path d="M56 26c0-4 3-7 7-7s7 3 7 7c0 4-3 5-5 7-1.5 1.5-2 2.5-2 4" />
      <circle cx="63" cy="42" r="0.75" fill="currentColor" />
    </g>
  ),
};

/**
 * `EmptyIllustration` — a built-in monoline drawing for `EmptyMedia
 * variant="default"`. 96×96 viewBox, `size-24` by default; strokes ride
 * `currentColor` so themes and the error tier need no extra assets.
 *
 * @example
 * <EmptyMedia variant="default">
 *   <EmptyIllustration name="clipboard" className="text-muted-foreground" />
 * </EmptyMedia>
 */
function EmptyIllustration({
  name,
  className,
  ref,
  ...props
}: EmptyIllustrationProps) {
  return (
    <svg
      ref={ref}
      data-slot="empty-illustration"
      data-name={name}
      viewBox="0 0 96 96"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      className={cn("size-24 shrink-0", className)}
      {...props}
    >
      <IllustrationGround />
      {ILLUSTRATIONS[name]}
    </svg>
  );
}

/** Props accepted by `EmptyValue`. */
export type EmptyValueProps = React.ComponentPropsWithRef<"span">;

/**
 * `EmptyValue` — the inline empty tier (Wave 2): a single muted phrase for a
 * value slot that has nothing in it ("No value", "Not added to any lists").
 * It uses the contrast-safe `muted-foreground` role so the absence remains readable.
 *
 * @example
 * <PropertyRow label="Domain"><EmptyValue /></PropertyRow>
 */
function EmptyValue({ className, children, ...props }: EmptyValueProps) {
  return (
    <span
      data-slot="empty-value"
      className={cn("text-base text-muted-foreground", className)}
      {...props}
    >
      {children ?? "No value"}
    </span>
  );
}

export {
  Empty,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
  EmptyDescription,
  EmptyContent,
  EmptyIllustration,
  EmptyValue,
};

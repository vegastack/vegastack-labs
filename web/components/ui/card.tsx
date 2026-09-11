import * as React from "react";
import { cn } from "@vegastack/design";

/**
 * Props shared by every `Card` part. Each part is a plain, server-safe `div`
 * with a forwarded ref and a `data-slot` for styling/targeting.
 */
export type CardProps = React.ComponentProps<"div"> & {
  /**
   * Density of the card. `sm` tightens the internal padding and gaps.
   * @default "default"
   */
  size?: "default" | "sm";
};

/**
 * `Card` — a borders-only surface for grouping related content (no shadows, per
 * the design system). Compose with `CardHeader`, `CardTitle`,
 * `CardDescription`, `CardAction`, `CardContent`, and `CardFooter`.
 *
 * Pure presentational and server-safe — no hooks, no `'use client'`.
 *
 * @example
 * <Card>
 *   <CardHeader>
 *     <CardTitle>Team plan</CardTitle>
 *     <CardDescription>$20 / user / month</CardDescription>
 *   </CardHeader>
 *   <CardContent>Everything in Pro, plus SSO and audit logs.</CardContent>
 *   <CardFooter>
 *     <Button>Upgrade</Button>
 *   </CardFooter>
 * </Card>
 */
function Card({ className, size = "default", ref, ...props }: CardProps) {
  return (
    <div
      ref={ref}
      data-slot="card"
      data-size={size}
      className={cn(
        "group/card flex flex-col gap-4 overflow-hidden rounded-lg border border-border bg-card py-4 text-base text-card-foreground",
        "has-data-[slot=card-footer]:pb-0",
        "data-[size=sm]:gap-3 data-[size=sm]:py-3 data-[size=sm]:has-data-[slot=card-footer]:pb-0",
        className,
      )}
      {...props}
    />
  );
}

/** Props accepted by `CardHeader`. */
export type CardHeaderProps = React.ComponentProps<"div">;

/**
 * `CardHeader` — top region holding the title, description, and optional action.
 * Switches to a two-column grid when a `CardAction` is present.

 *
 * @example
 * <CardHeader />
 */
function CardHeader({ className, ref, ...props }: CardHeaderProps) {
  return (
    <div
      ref={ref}
      data-slot="card-header"
      className={cn(
        "grid auto-rows-min grid-rows-[auto_auto] items-start gap-1 px-4",
        "has-data-[slot=card-action]:grid-cols-[1fr_auto]",
        "group-data-[size=sm]/card:px-3",
        className,
      )}
      {...props}
    />
  );
}

/** Props accepted by `CardTitle`. */
export type CardTitleProps = React.ComponentProps<"div">;

/** `CardTitle` — the heading line of a card (`data-slot="card-title"`).
 *
 * @example
 * <CardTitle />
 */
function CardTitle({ className, ref, ...props }: CardTitleProps) {
  return (
    <div
      ref={ref}
      data-slot="card-title"
      className={cn("text-h4 group-data-[size=sm]/card:text-label", className)}
      {...props}
    />
  );
}

/** Props accepted by `CardDescription`. */
export type CardDescriptionProps = React.ComponentProps<"div">;

/** `CardDescription` — supporting text under the title (muted).
 *
 * @example
 * <CardDescription />
 */
function CardDescription({ className, ref, ...props }: CardDescriptionProps) {
  return (
    <div
      ref={ref}
      data-slot="card-description"
      className={cn("text-base text-muted-foreground", className)}
      {...props}
    />
  );
}

/** Props accepted by `CardAction`. */
export type CardActionProps = React.ComponentProps<"div">;

/**
 * `CardAction` — an optional control (button, menu, switch) anchored to the
 * top-right of the header. Place it inside `CardHeader`.

 *
 * @example
 * <CardAction />
 */
function CardAction({ className, ref, ...props }: CardActionProps) {
  return (
    <div
      ref={ref}
      data-slot="card-action"
      className={cn(
        "col-start-2 row-span-2 row-start-1 self-start justify-self-end",
        className,
      )}
      {...props}
    />
  );
}

/** Props accepted by `CardContent`. */
export type CardContentProps = React.ComponentProps<"div">;

/** `CardContent` — the main body region of a card.
 *
 * @example
 * <CardContent />
 */
function CardContent({ className, ref, ...props }: CardContentProps) {
  return (
    <div
      ref={ref}
      data-slot="card-content"
      className={cn("px-4 group-data-[size=sm]/card:px-3", className)}
      {...props}
    />
  );
}

/** Props accepted by `CardFooter`. */
export type CardFooterProps = React.ComponentProps<"div">;

/**
 * `CardFooter` — a bottom region (typically actions) with a top border and a
 * subtle muted background. Borders-only — no shadow.

 *
 * @example
 * <CardFooter />
 */
function CardFooter({ className, ref, ...props }: CardFooterProps) {
  return (
    <div
      ref={ref}
      data-slot="card-footer"
      className={cn(
        "flex items-center rounded-b-lg border-t border-border bg-muted/(--alpha-wash) p-4 group-data-[size=sm]/card:p-3",
        className,
      )}
      {...props}
    />
  );
}

export {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardAction,
  CardContent,
  CardFooter,
};

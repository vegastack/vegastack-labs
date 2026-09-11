"use client";

import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { Avatar as BaseAvatar } from "@base-ui/react/avatar";
import { cn } from "@vegastack/design";

/* ------------------------------------------------------------------------------------------------
 * Avatar variants — `size` drives the diameter and the fallback text scale. Every value is a
 * semantic token / scale utility (no hardcoded px or palettes). The root is always `rounded-full`
 * with a neutral `bg-accent` fallback surface (the canonical avatar fill — `accent` is the neutral
 * hover/selected fill, never a colour) so an in-flight or failed image never flashes transparent;
 * `text-foreground` keeps the initials legible. Sizes follow the system control scale — 24 / 28 /
 * 32 (default) / 40 — plus a roomy `xl` (48).
 * ----------------------------------------------------------------------------------------------*/

export const avatarVariants = cva(
  "group/avatar relative inline-flex shrink-0 select-none items-center justify-center overflow-hidden rounded-full bg-accent align-middle text-foreground",
  {
    variants: {
      size: {
        xs: "size-6 text-sm",
        sm: "size-(--size-sm) text-base",
        default: "size-(--size-md) text-base",
        lg: "size-(--size-lg) text-lg",
        xl: "size-12 text-xl",
      },
    },
    defaultVariants: { size: "default" },
  },
);

type AvatarImageContract =
  | {
      /**
       * Image source. Pass a fully-resolved, public URL — this component is
       * purely presentational and does NOT resolve storage keys. R2 (or any CDN)
       * key → URL resolution stays app-side; resolve before passing `src`.
       */
      src: string;
      /**
       * Accessible alt text describing who/what the avatar represents (usually
       * the person's name). Pass `alt=""` only when the avatar image is purely
       * decorative and an adjacent control/text already names the entity.
       */
      alt: string;
    }
  | {
      /** No image source; only the fallback/root renders. */
      src?: undefined;
      /** Optional because no `<img>` is rendered when `src` is absent. */
      alt?: string;
    };

/** Props accepted by `Avatar`. */
export type AvatarProps = Omit<
  React.ComponentProps<typeof BaseAvatar.Root>,
  "children"
> &
  VariantProps<typeof avatarVariants> &
  AvatarImageContract & {
    /**
     * Fallback content shown while the image loads or when it fails / is absent —
     * typically 1–2 uppercase initials. Falls back to rendering nothing (the bare
     * `bg-accent` circle) when omitted.
     */
    fallback?: React.ReactNode;
    /**
     * How long to wait (ms) before showing the `fallback`, to avoid a flash for
     * fast-loading images. Forwarded to Base UI `Avatar.Fallback`.
     */
    fallbackDelay?: number;
    /**
     * Diameter of the avatar — also scales the fallback text.
     * @default 'default'
     */
    size?: "xs" | "sm" | "default" | "lg" | "xl";
  };

/**
 * `Avatar` — a circular user/entity image with an initials (or icon) fallback.
 * Built on Base UI `Avatar` (`Root` → `Image` → `Fallback`): the image only
 * paints once it has loaded, and the `fallback` shows while loading or on error,
 * so there is never a broken-image icon.
 *
 * **Presentational only (G7 split).** It takes a resolved `src` and does NOT
 * fetch data or resolve storage keys. Resolve R2/CDN keys to public URLs in the
 * app before passing them in.
 *
 * @example
 * <Avatar src="https://cdn.example.com/u/ada.webp" alt="Ada Lovelace" fallback="AL" />
 * <Avatar src="/decorative.png" alt="" fallback="AL" /> // decorative image; adjacent text names user
 * <Avatar fallback="AL" />            // no src → initials
 * <Avatar size="lg" fallback={<UserIcon />} />
 */
export function Avatar({
  className,
  size = "default",
  src,
  alt,
  fallback,
  fallbackDelay,
  ref,
  ...props
}: AvatarProps) {
  return (
    <BaseAvatar.Root
      ref={ref}
      data-slot="avatar"
      data-size={size}
      className={cn(avatarVariants({ size }), className)}
      {...props}
    >
      {src ? (
        <BaseAvatar.Image
          data-slot="avatar-image"
          src={src}
          alt={alt}
          className="aspect-square size-full object-cover"
        />
      ) : null}
      <BaseAvatar.Fallback
        data-slot="avatar-fallback"
        delay={fallbackDelay}
        className="flex size-full items-center justify-center font-medium uppercase [&_svg]:size-1/2"
      >
        {fallback}
      </BaseAvatar.Fallback>
    </BaseAvatar.Root>
  );
}

/* ------------------------------------------------------------------------------------------------
 * AvatarGroup — an overlapping stack of avatars. Negative inline spacing tucks each avatar under
 * the previous one; a `ring-background` on every child cuts a clean gap so they read as separate.
 * Compose a trailing `Avatar` with a `fallback` like "+5" to indicate overflow.
 * ----------------------------------------------------------------------------------------------*/

export const avatarGroupVariants = cva(
  "flex items-center *:data-[slot=avatar]:ring-2 *:data-[slot=avatar]:ring-background",
  {
    variants: {
      /** Stack overlap — how far each avatar tucks under the previous one. */
      spacing: {
        tight: "-space-x-3 rtl:space-x-reverse",
        default: "-space-x-2 rtl:space-x-reverse",
        loose: "-space-x-1 rtl:space-x-reverse",
      },
    },
    defaultVariants: { spacing: "default" },
  },
);

/** Props accepted by `AvatarGroup`. */
export interface AvatarGroupProps
  extends
    React.ComponentProps<"div">,
    VariantProps<typeof avatarGroupVariants> {
  /**
   * Overlap density of the stack.
   * - `tight`: avatars tuck furthest under one another.
   * - `default`: balanced overlap (default).
   * - `loose`: minimal overlap.
   * @default 'default'
   */
  spacing?: "tight" | "default" | "loose";
}

/**
 * `AvatarGroup` — an overlapping stack of `Avatar`s (e.g. project collaborators).
 * Each child gets a `ring-background` so the overlap reads cleanly on any
 * surface. Add a trailing `Avatar` with a `+N` fallback to show overflow.
 *
 * @example
 * <AvatarGroup>
 *   <Avatar src={a} alt="Ada" fallback="AL" />
 *   <Avatar src={b} alt="Linus" fallback="LT" />
 *   <Avatar fallback="+3" />
 * </AvatarGroup>
 */
export function AvatarGroup({
  className,
  spacing = "default",
  ref,
  ...props
}: AvatarGroupProps) {
  return (
    <div
      ref={ref}
      data-slot="avatar-group"
      className={cn(avatarGroupVariants({ spacing }), className)}
      {...props}
    />
  );
}

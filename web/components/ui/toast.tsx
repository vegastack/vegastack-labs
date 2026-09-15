"use client";

// Canonical registry source for the Toast surface. The package provider
// (`packages/ui/src/provider/toaster.tsx`) is mirrored from this implementation;
// the registry header stamp is the only intentional difference. That mirror is a
// byte-for-byte copy into a file that has NO `@/components/ui/*` alias, so this
// module must never import another registry item — every recipe it needs is local.

import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import {
  Toast as BaseToast,
  type ToastManager,
  type ToastManagerAddOptions,
  type ToastManagerPromiseOptions,
  type ToastManagerUpdateOptions,
} from "@base-ui/react/toast";
import {
  AlertTriangle,
  CircleCheck,
  Info,
  Loader,
  X,
  XCircle,
  type LucideIcon,
} from "lucide-react";
import { cn, fillInteractive, type FillTone } from "@vegastack/design";
import { useInternalThemeScope } from "@vegastack/design/theme-scope";

/* ------------------------------------------------------------------------------------------------
 * Types
 * ----------------------------------------------------------------------------------------------*/

/**
 * The toast tone vocabulary.
 *
 * `success` / `error` / `loading` are **reserved by the engine**, not chosen by us: Base UI's own
 * `promise()` writes `type: 'loading'` then `type: 'success' | 'error'` (see
 * `@base-ui/react/toast/store.js`), and its timer explicitly skips auto-dismiss while
 * `type === 'loading'`. Renaming `error` to `destructive` would therefore leave every promise
 * rejection unstyled. So the type strings follow the engine and the *tokens* follow the house
 * families: `error` paints with the `destructive` family.
 */
export type ToastType =
  "default" | "success" | "error" | "warning" | "info" | "loading";

/**
 * Custom data carried on a toast. `render` replaces the toast BODY while keeping the stacking,
 * swipe-to-dismiss and focus behaviour of a real `Toast.Root` — the Base UI equivalent of a
 * fully custom toast.
 */
export interface ToastData {
  /** Render the toast's body yourself. Receives the live toast object. */
  render?: (toast: ToastItem) => React.ReactNode;
}

/** One toast in the list, as handed to `Toast` / a custom `render`. */
export type ToastItem = BaseToast.Root.ToastObject<ToastData>;

/** Options accepted by every `toast.*` call — Base UI's add options minus the parts we set. */
export type ToastOptions = Omit<
  ToastManagerAddOptions<ToastData>,
  "title" | "type"
>;

/** Options accepted by `toast.update(id, options)`. */
export type ToastUpdateOptions = ToastManagerUpdateOptions<ToastData>;

/** Options accepted by `toast.promise(promise, options)`. */
export type ToastPromiseOptions<Value> = ToastManagerPromiseOptions<
  Value,
  ToastData
>;

/* ------------------------------------------------------------------------------------------------
 * Manager — the imperative API
 * ----------------------------------------------------------------------------------------------*/

/**
 * The app-wide toast manager. Created at module scope so `toast()` works from anywhere —
 * event handlers, route handlers' client callbacks, plain functions outside the React tree —
 * and handed to `ToastProvider` so every call lands in the one mounted viewport.
 */
export const toastManager = BaseToast.createToastManager<ToastData>();

/**
 * D23 (live-region policy) expressed as code: a toast is announced politely by default, and
 * urgently only when it reports a problem the user must notice. Base UI turns `priority: 'high'`
 * into a visually hidden `role="alert"` mirror of the title/description; `'low'` leaves the
 * announcement to the viewport's `aria-live="polite"` region.
 */
function priorityFor(type: ToastType): "low" | "high" {
  return type === "error" || type === "warning" ? "high" : "low";
}

function add(
  type: ToastType,
  title: React.ReactNode,
  options?: ToastOptions,
): string {
  return toastManager.add({
    ...options,
    title,
    type,
    priority: options?.priority ?? priorityFor(type),
  });
}

/**
 * Base UI's `promise()` writes the three states itself and does not know about D23, so each
 * state's options are normalized here and given the priority its type earns. A bare string is
 * Base UI's shortcut for `description`, which this preserves.
 */
function promiseState<T>(
  value:
    string | ToastUpdateOptions | ((arg: T) => string | ToastUpdateOptions),
  type: ToastType,
): typeof value {
  const normalize = (raw: string | ToastUpdateOptions): ToastUpdateOptions => ({
    priority: priorityFor(type),
    ...(typeof raw === "string" ? { description: raw } : raw),
  });
  return typeof value === "function"
    ? (arg: T) =>
        normalize((value as (arg: T) => string | ToastUpdateOptions)(arg))
    : normalize(value);
}

/**
 * `toast` — the imperative notification API. Requires a mounted {@link ToastProvider} and
 * {@link Toaster}; `<VegaStackProvider>` mounts both, so most apps only ever call this.
 *
 * Every call returns the toast id, which `toast.update` / `toast.dismiss` accept — and which
 * `toast()` itself accepts as `options.id` to upsert a toast in place rather than stacking a
 * second one.
 *
 * @example
 * toast.success("Changes saved", { description: "main@a1f7c2 is live" });
 */
export const toast = Object.assign(
  /** Show a neutral toast. */
  (title: React.ReactNode, options?: ToastOptions) =>
    add("default", title, options),
  {
    /** Success toast — success tint + `CircleCheck`, announced politely. */
    success: (title: React.ReactNode, options?: ToastOptions) =>
      add("success", title, options),
    /** Error toast — destructive tint + `XCircle`, announced urgently (D23). */
    error: (title: React.ReactNode, options?: ToastOptions) =>
      add("error", title, options),
    /** Warning toast — warning tint + `AlertTriangle`, announced urgently (D23). */
    warning: (title: React.ReactNode, options?: ToastOptions) =>
      add("warning", title, options),
    /** Info toast — info tint + `Info`, announced politely. */
    info: (title: React.ReactNode, options?: ToastOptions) =>
      add("info", title, options),
    /**
     * Pending toast with a spinner. Base UI suppresses the auto-dismiss timer for the whole
     * `loading` type, so this toast stays until you resolve it — reuse the returned id with
     * `toast.success` / `toast.error` / `toast.dismiss`.
     */
    loading: (title: React.ReactNode, options?: ToastOptions) =>
      add("loading", title, options),
    /**
     * Render a fully custom body inside a real toast — stacking, swipe-to-dismiss, Escape and
     * the viewport's live region all still apply. The callback receives the toast object.
     */
    custom: (
      render: (item: ToastItem) => React.ReactNode,
      options?: ToastOptions,
    ) => toastManager.add({ ...options, data: { ...options?.data, render } }),
    /**
     * Drive one toast through loading → success / error from a promise. Resolves/rejects with
     * the original promise's value, so it composes with `await`. The rejection branch is
     * announced urgently (D23) without the caller having to say so.
     */
    promise: <Value,>(
      promise: Promise<Value>,
      options: ToastPromiseOptions<Value>,
    ) =>
      toastManager.promise(promise, {
        ...options,
        loading: promiseState(
          options.loading,
          "loading",
        ) as typeof options.loading,
        success: promiseState<Value>(
          options.success,
          "success",
        ) as typeof options.success,
        error: promiseState(options.error, "error") as typeof options.error,
      }),
    /**
     * Update a live toast in place (refreshing its auto-dismiss timer). Changing the `type`
     * re-derives the announcement priority unless you set one explicitly.
     */
    update: (id: string, options: ToastUpdateOptions) =>
      toastManager.update(id, {
        ...options,
        priority:
          options.priority ??
          (options.type ? priorityFor(toastTypeOf(options.type)) : undefined),
      }),
    /** Dismiss one toast, or every toast when called with no id. */
    dismiss: (id?: string) => toastManager.close(id),
  },
);

/**
 * `useToast` — Base UI's `useToastManager` typed to our {@link ToastData}. Returns the reactive
 * `toasts` array plus `add` / `close` / `update` / `promise`. Use it to build a custom toast
 * list; for firing a toast, the module-scope {@link toast} needs no hook.
 */
export function useToast() {
  return BaseToast.useToastManager<ToastData>();
}

/* ------------------------------------------------------------------------------------------------
 * Provider
 * ----------------------------------------------------------------------------------------------*/

/** Props accepted by `ToastProvider`. */
export interface ToastProviderProps {
  /**
   * The application subtree that can fire toasts.
   * @default undefined
   */
  children?: React.ReactNode;
  /**
   * Milliseconds before a toast auto-dismisses. `0` disables auto-dismiss.
   * The `loading` type never auto-dismisses regardless.
   * @default 5000
   */
  timeout?: number;
  /**
   * How many toasts render at once. Older toasts past the limit stay mounted, marked
   * `data-limited` (and `inert`), so they can animate out rather than vanish.
   * @default 3
   */
  limit?: number;
  /**
   * The manager toasts are queued into. Defaults to the module-scope {@link toastManager},
   * which is what makes the imperative `toast()` work from outside the React tree. Pass your
   * own only when you need a second, isolated toast channel.
   * @default toastManager
   */
  toastManager?: ToastManager<ToastData>;
}

/**
 * `ToastProvider` — the toast context. Mount it once, above everything that can fire a toast;
 * `<VegaStackProvider>` already does. Pair it with one {@link Toaster} for the visible viewport.
 *
 * @example
 * <ToastProvider limit={5}>
 *   {children}
 *   <Toaster />
 * </ToastProvider>
 */
export function ToastProvider({
  children,
  timeout,
  limit,
  toastManager: manager = toastManager,
}: ToastProviderProps) {
  return (
    <BaseToast.Provider toastManager={manager} timeout={timeout} limit={limit}>
      {children}
    </BaseToast.Provider>
  );
}

/* ------------------------------------------------------------------------------------------------
 * Surface recipes
 * ----------------------------------------------------------------------------------------------*/

/**
 * Where the stack pins itself. Names are LOGICAL on the inline axis (`start`/`end` rather than
 * left/right) so an RTL document mirrors the stack without a second position vocabulary.
 */
export type ToastPosition =
  | "top-start"
  | "top-center"
  | "top-end"
  | "bottom-start"
  | "bottom-center"
  | "bottom-end";

/**
 * The viewport recipe. `--toast-dir` is the stack's growth sign, read by every transform in
 * `toastVariants`: `-1` pins the stack to the bottom (toasts behind peek ABOVE the frontmost),
 * `1` pins it to the top. Insets are the house 24px spacing plus `env(safe-area-inset-*)`, so an
 * edge-pinned toast clears the iOS notch/home indicator — `env()` is `0px` elsewhere, so this is
 * a zero-visual-change default on every other device.
 */
const toastViewportVariants = cva(
  [
    "fixed z-(--z-toast) mx-auto w-[calc(100vw-var(--spacing)*8)] sm:w-(--panel-width-lg)",
    "[--toast-gap:calc(var(--spacing)*3)] [--toast-peek:calc(var(--spacing)*3)]",
    "top-[calc(var(--spacing)*6+env(safe-area-inset-top))]",
    "bottom-[calc(var(--spacing)*6+env(safe-area-inset-bottom))]",
    "start-[calc(var(--spacing)*6+env(safe-area-inset-left))]",
    "end-[calc(var(--spacing)*6+env(safe-area-inset-right))]",
  ].join(" "),
  {
    variants: {
      position: {
        "top-start": "bottom-auto end-auto [--toast-dir:1]",
        "top-center": "bottom-auto start-0 end-0 [--toast-dir:1]",
        "top-end": "bottom-auto start-auto [--toast-dir:1]",
        "bottom-start": "top-auto end-auto [--toast-dir:-1]",
        "bottom-center": "top-auto start-0 end-0 [--toast-dir:-1]",
        "bottom-end": "top-auto start-auto [--toast-dir:-1]",
      },
    },
    defaultVariants: { position: "bottom-end" },
  },
);

/**
 * The toast surface. Two things are happening here, and they are worth keeping apart:
 *
 * 1. **The surface** — the floating-family recipe: the popover ground, the one hairline border,
 *    `rounded-lg`, `shadow-overlay`, and 16px padding (D14). A tinted type swaps the ground for
 *    its `{family}-subtle` fill and its ink for `{family}-text`, exactly as `Alert` does, so the
 *    two status surfaces stay one design. Per the surface-ladder decision, a floating surface is
 *    never a rung of its own — no `surface-2` here.
 *
 * 2. **The stack** — Base UI publishes `--toast-index`, `--toast-offset-y`,
 *    `--toast-height`/`--toast-frontmost-height` and the two swipe-movement vars; the transforms
 *    below are the collapsed stack (each toast behind scaled down and peeking by `--toast-peek`),
 *    the expanded stack (`data-expanded`, when the viewport is hovered or focused), and the
 *    swipe/dismiss exits. Every vertical term is multiplied by `--toast-dir` so one expression
 *    serves both a top- and a bottom-pinned stack.
 */
const toastVariants = cva(
  [
    "group/toast absolute start-0 end-0 w-full select-none",
    "[--toast-scale:calc(max(0,1-(var(--toast-index)*0.1)))]",
    "[--toast-shrink:calc(1-var(--toast-scale))]",
    "[--toast-h:var(--toast-frontmost-height,var(--toast-height))]",
    "[--toast-offset:calc(var(--toast-swipe-movement-y)+var(--toast-dir)*(var(--toast-offset-y)+var(--toast-index)*var(--toast-gap)))]",
    "h-(--toast-h) data-expanded:h-(--toast-height)",
    // The stacking order mirrors the visual order: index 0 is the frontmost toast.
    "z-[calc(var(--z-toast)-var(--toast-index))]",
    "rounded-lg border p-4 text-base shadow-overlay",
    // Collapsed: scale each toast behind the front one down and let it peek out by --toast-peek.
    "[transform:translateX(var(--toast-swipe-movement-x))_translateY(calc(var(--toast-swipe-movement-y)+var(--toast-dir)*(var(--toast-index)*var(--toast-peek)+var(--toast-shrink)*var(--toast-h))))_scale(var(--toast-scale))]",
    // Expanded (viewport hovered or focused): lay the stack out at its natural heights.
    "data-expanded:[transform:translateX(var(--toast-swipe-movement-x))_translateY(var(--toast-offset))]",
    // Enter/exit: the toast travels in from beyond its own edge. `--toast-dir` gives it the
    // right sign for a top- or bottom-pinned stack.
    "data-starting-style:[transform:translateY(calc(var(--toast-dir)*-150%))]",
    "data-ending-style:opacity-0",
    "[&[data-ending-style]:not([data-limited]):not([data-swipe-direction])]:[transform:translateY(calc(var(--toast-dir)*-150%))]",
    // A swiped toast leaves along the axis it was swiped on, from wherever the finger left it.
    "data-ending-style:data-[swipe-direction=up]:[transform:translateY(calc(var(--toast-swipe-movement-y)-150%))]",
    "data-ending-style:data-[swipe-direction=down]:[transform:translateY(calc(var(--toast-swipe-movement-y)+150%))]",
    "data-ending-style:data-[swipe-direction=left]:[transform:translateX(calc(var(--toast-swipe-movement-x)-150%))_translateY(var(--toast-offset))]",
    "data-ending-style:data-[swipe-direction=right]:[transform:translateX(calc(var(--toast-swipe-movement-x)+150%))_translateY(var(--toast-offset))]",
    // A toast pushed past `limit` stays mounted (and inert) so it can fade rather than vanish.
    "data-limited:opacity-0",
    // The gap between stacked toasts is dead space the pointer would otherwise cross, collapsing
    // the stack mid-hover. This bridges it.
    "after:absolute after:inset-x-0 after:h-(--toast-gap) after:content-['']",
    "transition-[transform,opacity,height] duration-base ease-standard",
  ].join(" "),
  {
    variants: {
      type: {
        default:
          "border-border bg-popover text-popover-foreground [&_[data-slot=toast-description]]:text-muted-foreground",
        loading:
          "border-border bg-popover text-popover-foreground [&_[data-slot=toast-description]]:text-muted-foreground",
        success:
          "border-success/(--alpha-border-subtle) bg-success-subtle text-success-text",
        error:
          "border-destructive/(--alpha-border-subtle) bg-destructive-subtle text-destructive-text",
        warning:
          "border-warning/(--alpha-border-subtle) bg-warning-subtle text-warning-text",
        info: "border-info/(--alpha-border-subtle) bg-info-subtle text-info-text",
      },
      /** Which edge the stack grows from — sets `origin` so the collapsed scale reads right. */
      anchor: {
        top: "top-0 origin-top after:top-auto after:bottom-full",
        bottom: "bottom-0 origin-bottom after:top-full",
      },
    },
    defaultVariants: { type: "default", anchor: "bottom" },
  },
);

/** The type-to-variant map for a toast's leading icon. */
const TYPE_ICON: Record<Exclude<ToastType, "default">, LucideIcon> = {
  success: CircleCheck,
  error: XCircle,
  warning: AlertTriangle,
  info: Info,
  loading: Loader,
};

/**
 * The ink each type's hover/pressed wash composites from. `fillInteractive` is the house recipe —
 * a control inside a tinted toast washes in its OWN family, never in a borrowed neutral.
 */
const TYPE_FILL: Record<ToastType, FillTone> = {
  default: "foreground",
  loading: "foreground",
  success: "success",
  error: "destructive",
  warning: "warning",
  info: "info",
};

/** Narrow the engine's free-form `type` string back onto our vocabulary. */
function toastTypeOf(type: string | undefined): ToastType {
  return type && type in TYPE_ICON ? (type as ToastType) : "default";
}

/* ------------------------------------------------------------------------------------------------
 * Parts
 * ----------------------------------------------------------------------------------------------*/

/** Props accepted by `ToastViewport`. */
export interface ToastViewportProps
  extends
    BaseToast.Viewport.Props,
    VariantProps<typeof toastViewportVariants> {}

/**
 * `ToastViewport` — the fixed, labelled notifications region the stack lives in. Base UI gives it
 * `role="region"`, `aria-live="polite"` and the F6 landmark shortcut; this adds the position, the
 * safe-area insets, the toast z-band, and the theme scope (it is portaled outside any nested
 * `.dark` wrapper, so it has to carry its scope class across the portal boundary).
 *
 * @example
 * <ToastViewport position="top-end">{list}</ToastViewport>
 */
export function ToastViewport({
  className,
  position,
  ...props
}: ToastViewportProps) {
  const themeScope = useInternalThemeScope();
  return (
    <BaseToast.Viewport
      data-slot="toast-viewport"
      className={cn(themeScope, toastViewportVariants({ position }), className)}
      {...props}
    />
  );
}

/** Props accepted by `ToastRoot`. */
export interface ToastRootProps
  extends
    Omit<BaseToast.Root.Props, "toast">,
    VariantProps<typeof toastVariants> {
  /** The toast to render. */
  toast: ToastItem;
}

/**
 * `ToastRoot` — one toast's surface and stacking behaviour, without any body. Compose it with
 * {@link ToastContent}, {@link ToastTitle} … when you build your own list; {@link Toast} is the
 * assembled default.
 *
 * @example
 * <ToastRoot toast={item}>{body}</ToastRoot>
 */
export function ToastRoot({
  className,
  toast: item,
  type,
  anchor,
  ...props
}: ToastRootProps) {
  const resolved = type ?? toastTypeOf(item.type);
  return (
    <BaseToast.Root
      toast={item}
      data-slot="toast"
      className={cn(toastVariants({ type: resolved, anchor }), className)}
      {...props}
    />
  );
}

/** Props accepted by `ToastContent`. */
export type ToastContentProps = BaseToast.Content.Props;

/**
 * `ToastContent` — the clipped body. It hides the overflow of a taller toast while the stack is
 * collapsed and fades back in when the viewport expands (`data-behind` / `data-expanded`).
 *
 * @example
 * <ToastContent><ToastTitle /></ToastContent>
 */
export function ToastContent({ className, ...props }: ToastContentProps) {
  return (
    <BaseToast.Content
      data-slot="toast-content"
      className={cn(
        "flex h-full items-start gap-3 overflow-hidden",
        "transition-opacity duration-fast ease-standard data-behind:opacity-0 data-expanded:opacity-100",
        className,
      )}
      {...props}
    />
  );
}

/** Props accepted by `ToastTitle`. */
export type ToastTitleProps = BaseToast.Title.Props;

/**
 * `ToastTitle` — the toast's leading line, at the 14/500 rung of the weight ladder. With no
 * children it renders the `title` from the toast object.
 *
 * @example
 * <ToastTitle />
 */
export function ToastTitle({ className, ...props }: ToastTitleProps) {
  return (
    <BaseToast.Title
      data-slot="toast-title"
      className={cn("text-base font-medium leading-tight", className)}
      {...props}
    />
  );
}

/** Props accepted by `ToastDescription`. */
export type ToastDescriptionProps = BaseToast.Description.Props;

/**
 * `ToastDescription` — the supporting line. On a neutral toast it drops to
 * `text-muted-foreground`; on a tinted one it stays in the family ink, which is the pair the
 * contrast gate validates (same rule as `Alert`).
 *
 * @example
 * <ToastDescription />
 */
export function ToastDescription({
  className,
  ...props
}: ToastDescriptionProps) {
  return (
    <BaseToast.Description
      data-slot="toast-description"
      className={cn("text-base", className)}
      {...props}
    />
  );
}

/** Props accepted by `ToastAction`. */
export interface ToastActionProps extends BaseToast.Action.Props {
  /**
   * Which ink the hover/pressed wash composites from. `Toast` sets it from the toast's type, so a
   * control inside a tinted toast washes in its own family rather than a borrowed neutral.
   * @default 'foreground'
   */
  tone?: FillTone;
}

/**
 * `ToastAction` — the toast's one affirmative control ("Undo", "Retry"). It wears the `soft` button
 * face in the toast's own family, so a toast never introduces a second hue. Its label and handler
 * come from the toast's `actionProps`.
 *
 * @example
 * <ToastAction tone="destructive" />
 */
export function ToastAction({
  className,
  tone = "foreground",
  ...props
}: ToastActionProps) {
  return (
    <BaseToast.Action
      data-slot="toast-action"
      className={cn(
        "inline-flex h-(--size-xs) shrink-0 items-center justify-center rounded-md px-2 text-base font-medium",
        "border border-current/(--alpha-border-subtle) bg-current/(--alpha-surface-faint)",
        fillInteractive[tone],
        className,
      )}
      {...props}
    />
  );
}

/** Props accepted by `ToastClose`. */
export interface ToastCloseProps extends BaseToast.Close.Props {
  /**
   * Which ink the hover/pressed wash composites from. `Toast` sets it from the toast's type.
   * @default 'foreground'
   */
  tone?: FillTone;
}

/**
 * `ToastClose` — the dismiss control. Sized to the 24px `xs` tier so the effective pointer target
 * clears the 24px floor without an extra hit area.
 *
 * @example
 * <ToastClose aria-label="Dismiss notification" />
 */
export function ToastClose({
  className,
  children,
  tone = "foreground",
  ...props
}: ToastCloseProps) {
  return (
    <BaseToast.Close
      data-slot="toast-close"
      className={cn(
        "inline-flex size-(--size-xs) shrink-0 items-center justify-center rounded-md",
        fillInteractive[tone],
        "[&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-(--icon-inline)",
        className,
      )}
      {...props}
    >
      {children ?? <X aria-hidden />}
    </BaseToast.Close>
  );
}

/** Props accepted by `ToastPositioner`. */
export type ToastPositionerProps = BaseToast.Positioner.Props;

/**
 * `ToastPositioner` — the anchored-toast wrapper. Base UI can anchor a toast to an element
 * instead of stacking it in the corner (pass `positionerProps.anchor` on the `toast()` call);
 * this is the positioner that surface needs, in the toast z-band.
 *
 * @example
 * <ToastPositioner toast={item}><ToastRoot toast={item} /></ToastPositioner>
 */
export function ToastPositioner({ className, ...props }: ToastPositionerProps) {
  return (
    <BaseToast.Positioner
      data-slot="toast-positioner"
      className={cn("z-(--z-toast)", className)}
      {...props}
    />
  );
}

/** Props accepted by `ToastArrow`. */
export type ToastArrowProps = BaseToast.Arrow.Props;

/**
 * `ToastArrow` — the anchored toast's pointer, tinted to the surface it grows from.
 *
 * @example
 * <ToastArrow />
 */
export function ToastArrow({ className, ...props }: ToastArrowProps) {
  return (
    <BaseToast.Arrow
      data-slot="toast-arrow"
      className={cn("text-current", className)}
      {...props}
    />
  );
}

/** Props accepted by `ToastPortal`. */
export type ToastPortalProps = BaseToast.Portal.Props;

/**
 * `ToastPortal` — the host that moves the viewport out to `<body>`. Re-exported unchanged for
 * consumers composing their own stack; `Toaster` already renders it. Whatever you put inside must
 * carry the theme scope, because the portal lands outside every nested scope wrapper.
 */
export const ToastPortal: React.FC<ToastPortalProps> = BaseToast.Portal;

/* ------------------------------------------------------------------------------------------------
 * The assembled toast
 * ----------------------------------------------------------------------------------------------*/

/** Props accepted by `Toast`. */
export interface ToastProps extends Omit<ToastRootProps, "children"> {
  /**
   * Show the dismiss X. Off only for toasts that must be resolved by their action.
   * @default true
   */
  closeButton?: boolean;
  /** Accessible name for the dismiss control. @default 'Dismiss notification' */
  closeLabel?: string;
}

/**
 * `Toast` — the default assembled toast: leading status icon, title, description, the optional
 * action from `actionProps`, and the dismiss X. When the toast carries `data.render` (what
 * `toast.custom()` sets) that renderer owns the body instead, and the stacking, swipe-to-dismiss,
 * Escape handling and live-region announcement all still apply.
 *
 * @example
 * <Toast toast={item} />
 */
export function Toast({
  toast: item,
  closeButton = true,
  closeLabel = "Dismiss notification",
  ...props
}: ToastProps) {
  const type = toastTypeOf(item.type);
  const Icon = type === "default" ? null : TYPE_ICON[type];
  const custom = item.data?.render;
  return (
    <ToastRoot toast={item} {...props}>
      <ToastContent>
        {custom ? (
          custom(item)
        ) : (
          <>
            {Icon ? (
              <Icon
                data-slot="toast-icon"
                aria-hidden
                className={cn(
                  "mt-0.5 size-(--icon-default) shrink-0",
                  type === "loading" && "animate-spin",
                )}
              />
            ) : null}
            <div className="flex min-w-0 flex-1 flex-col gap-1">
              <ToastTitle />
              <ToastDescription />
            </div>
            {item.actionProps ? <ToastAction tone={TYPE_FILL[type]} /> : null}
          </>
        )}
        {closeButton ? (
          <ToastClose aria-label={closeLabel} tone={TYPE_FILL[type]} />
        ) : null}
      </ToastContent>
    </ToastRoot>
  );
}

/* ------------------------------------------------------------------------------------------------
 * Toaster
 * ----------------------------------------------------------------------------------------------*/

/** Props accepted by `Toaster`. */
export interface ToasterProps extends Omit<ToastViewportProps, "children"> {
  /**
   * Which corner the stack pins to. Inline names are logical, so `bottom-end` is bottom-right in
   * an LTR document and bottom-left in an RTL one.
   * @default 'bottom-end'
   */
  position?: ToastPosition;
  /**
   * Direction(s) a toast can be swiped to dismiss. Defaults to the stack's own block direction
   * plus both inline directions, which reads the same under either text direction.
   * @default ['down' | 'up', 'left', 'right'] — the block direction follows `position`
   */
  swipeDirection?: BaseToast.Root.Props["swipeDirection"];
  /** Show the dismiss X on every toast. @default true */
  closeButton?: boolean;
  /**
   * Render every toast's body yourself. A per-toast `data.render` (from `toast.custom()`) wins
   * over this. Named `renderToast` because `render` is Base UI's polymorphic element prop, which
   * the viewport keeps.
   * @default undefined — the assembled `Toast` body
   */
  renderToast?: (item: ToastItem) => React.ReactNode;
}

/**
 * `Toaster` — the visible toast stack. Mount it **once**, inside a {@link ToastProvider};
 * `<VegaStackProvider>` does both, so most apps never render either directly — they just call
 * {@link toast}.
 *
 * Toasts stack collapsed and expand when the viewport is hovered or focused. <kbd>F6</kbd> jumps
 * focus into the viewport from anywhere on the page and <kbd>Escape</kbd> dismisses the focused
 * toast — both are Base UI's, and both are why the stack is a labelled landmark region rather
 * than a pile of divs.
 *
 * Note: this is a mount-once portal host and Base UI owns its DOM, so it exposes no ref.
 *
 * @example
 * <Toaster position="top-end" />
 */
export function Toaster({
  className,
  position = "bottom-end",
  swipeDirection,
  closeButton = true,
  renderToast,
  ...props
}: ToasterProps) {
  const { toasts } = useToast();
  // The viewport applies the theme scope itself (so a hand-composed viewport is still scoped),
  // but the scope has to be attached inside THIS portal subtree too — the portal jumps to
  // <body>, outside any nested `.dark` wrapper, and only the class re-establishes it.
  const themeScope = useInternalThemeScope();
  const anchor = position.startsWith("top") ? "top" : "bottom";
  const swipe =
    swipeDirection ??
    (anchor === "top"
      ? (["up", "left", "right"] as const)
      : (["down", "left", "right"] as const));
  return (
    <BaseToast.Portal>
      <ToastViewport
        position={position}
        className={cn(themeScope, className)}
        {...props}
      >
        {toasts.map((item) =>
          renderToast && !item.data?.render ? (
            <ToastRoot
              key={item.id}
              toast={item}
              anchor={anchor}
              swipeDirection={swipe}
            >
              <ToastContent>{renderToast(item)}</ToastContent>
            </ToastRoot>
          ) : (
            <Toast
              key={item.id}
              toast={item}
              anchor={anchor}
              swipeDirection={swipe}
              closeButton={closeButton}
            />
          ),
        )}
      </ToastViewport>
    </BaseToast.Portal>
  );
}

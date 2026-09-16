"use client";

import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import {
  AlertTriangle,
  CircleCheck,
  Info,
  X,
  XCircle,
  type LucideIcon,
} from "lucide-react";
import { cn } from "@vegastack/design";
import { IconButton } from "@/components/ui/icon-button";

/**
 * Alert variants — `default` (neutral) plus four semantic statuses. Per the
 * v2 spec each status uses its `{family}` subtle
 * tint (`bg-X-subtle text-X-text border-X/20`), radius `md`, and is always paired
 * with a leading icon. Every value is a semantic token, never a hardcoded color.
 */
export const alertVariants = cva(
  "relative flex w-full items-start gap-3 rounded-md border p-4 text-base [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-(--icon-default)",
  {
    variants: {
      /**
       * Layout. `default` is the block alert; `strip` (Wave 2 — the settings
       * info-banner) is a compact single-line ribbon: centered icon + copy,
       * tighter padding, inline-sized icon.
       */
      variant: {
        default: "",
        strip:
          "items-center gap-2 px-3 py-2 [&_svg:not([class*='size-'])]:size-(--icon-inline)",
      },
      intent: {
        default: "border-border bg-card text-card-foreground",
        info: "border-info/(--alpha-border-subtle) bg-info-subtle text-info-text",
        success:
          "border-success/(--alpha-border-subtle) bg-success-subtle text-success-text",
        warning:
          "border-warning/(--alpha-border-subtle) bg-warning-subtle text-warning-text",
        destructive:
          "border-destructive/(--alpha-border-subtle) bg-destructive-subtle text-destructive-text",
      },
    },
    defaultVariants: { variant: "default", intent: "default" },
  },
);

/** The status intents Alert supports. */
export type AlertIntent = NonNullable<
  VariantProps<typeof alertVariants>["intent"]
>;

/** Default leading icon per status intent (overridable via `icon` / `hideIcon`). */
const VARIANT_ICON: Record<AlertIntent, LucideIcon> = {
  default: Info,
  info: Info,
  success: CircleCheck,
  warning: AlertTriangle,
  destructive: XCircle,
};

/** Props accepted by `Alert`. */
export interface AlertProps
  extends
    React.ComponentPropsWithRef<"div">,
    VariantProps<typeof alertVariants> {
  /**
   * Layout — `default` block alert, or `strip`: the compact single-line info
   * ribbon (settings banners, inline notices).
   * @default "default"
   */
  variant?: "default" | "strip";
  /**
   * Status intent — drives the color tokens and the default leading icon.
   * @default "default"
   */
  intent?: AlertIntent;
  /**
   * Custom leading icon. Falls back to the intent's default icon.
   * Pass a `lucide-react` icon element (e.g. `<Bell />`).

   * @default undefined
   */
  icon?: React.ReactNode;
  /**
   * Hide the leading icon entirely (overrides `icon`).
   * @default false
   */
  hideIcon?: boolean;
  /**
   * Render a dismiss (close) button in the top-right corner.
   * @default false
   */
  dismissable?: boolean;
  /**
   * Called when the dismiss button is clicked. When `dismissable` is set and no
   * handler is provided, the alert removes itself from the DOM internally.

   * @default undefined
   */
  onDismiss?: () => void;
  /**
   * Accessible label for the dismiss button.
   * @default "Dismiss"
   */
  dismissLabel?: string;
  /**
   * Mark this alert as a runtime announcement — it appeared (or its copy changed) AFTER the page
   * had settled, in response to something the user did. Only then does an assertive
   * `role="alert"` become correct, and only for `destructive`/`warning`; every other intent stays
   * polite. Leave `false` for a statically rendered banner: a `status` region that is already in
   * the DOM at load announces nothing, so a page of three static alerts stays silent instead of
   * interrupting three times (D23, WAI-ARIA `alert` is for time-sensitive, important messages).
   * @default false
   */
  live?: boolean;
}

/** Intents whose runtime announcement is urgent enough for an assertive `role="alert"` (D23). */
const ASSERTIVE_INTENTS: ReadonlySet<AlertIntent> = new Set([
  "destructive",
  "warning",
]);

/**
 * `Alert` — a presentational status banner. Compose with
 * `AlertTitle`, `AlertDescription`, and `AlertActions`. Supports five status
 * variants, an optional leading icon, and an optional self-managing dismiss
 * button. Client-only because the dismiss button can manage local visibility.
 *
 * **Live-region policy (D23).** The banner is a polite `role="status"` by default, which announces
 * nothing when it is already present at page load and announces politely when it appears later.
 * Pass `live` for a banner rendered in response to a user action; with `live`, a `destructive` or
 * `warning` intent escalates to the assertive `role="alert"` — the only case that earns an
 * interruption.
 *
 * @example
 * <Alert intent="success">
 *   <AlertTitle>Saved</AlertTitle>
 *   <AlertDescription>Your changes have been saved.</AlertDescription>
 * </Alert>
 *
 * @example
 * <Alert intent="warning" dismissable onDismiss={() => setOpen(false)}>
 *   <AlertTitle>Subscription expiring</AlertTitle>
 *   <AlertDescription>Renew within 3 days to avoid interruption.</AlertDescription>
 *   <AlertActions>
 *     <Button variant="outline" tone="warning" size="sm">Renew now</Button>
 *   </AlertActions>
 * </Alert>
 */
function Alert({
  className,
  variant = "default",
  intent = "default",
  icon,
  hideIcon = false,
  dismissable = false,
  onDismiss,
  dismissLabel = "Dismiss",
  live = false,
  children,
  ...props
}: AlertProps) {
  const [open, setOpen] = React.useState(true);

  const handleDismiss = React.useCallback(() => {
    if (onDismiss) onDismiss();
    else setOpen(false);
  }, [onDismiss]);

  if (!open) return null;

  const DefaultIcon = VARIANT_ICON[intent];
  const leadingIcon = hideIcon ? null : (icon ?? <DefaultIcon aria-hidden />);
  // D23. `status` (implicit `aria-live="polite"`) is the default for every intent: a live region
  // already in the DOM at load announces nothing, so a static banner is silent, and a banner that
  // appears later is announced at the next pause. `live` says this banner IS a runtime
  // announcement — and only then does a destructive/warning intent earn the assertive `alert`
  // role, which interrupts whatever the screen reader is saying.
  const assertive = live && ASSERTIVE_INTENTS.has(intent);

  return (
    <div
      role={assertive ? "alert" : "status"}
      aria-live={assertive ? "assertive" : "polite"}
      aria-atomic={live ? true : undefined}
      data-live={live ? "" : undefined}
      data-slot="alert"
      data-variant={variant}
      data-intent={intent}
      className={cn(
        alertVariants({ variant, intent }),
        dismissable && "pr-10",
        className,
      )}
      {...props}
    >
      {leadingIcon ? (
        <span
          data-slot="alert-icon"
          className={cn("shrink-0", variant === "strip" ? undefined : "mt-0.5")}
        >
          {leadingIcon}
        </span>
      ) : null}
      <div
        data-slot="alert-content"
        className="flex min-w-0 flex-1 flex-col gap-1"
      >
        {children}
      </div>
      {dismissable ? (
        <IconButton
          variant="ghost"
          size="xs"
          data-slot="alert-dismiss"
          onClick={handleDismiss}
          aria-label={dismissLabel}
          className="absolute top-2 end-2 text-current"
        >
          <X />
        </IconButton>
      ) : null}
    </div>
  );
}

/** Props accepted by `AlertTitle`. */
export type AlertTitleProps = React.ComponentPropsWithRef<"div">;

/** `AlertTitle` — the emphasized leading line of an alert.
 *
 * @example
 * <AlertTitle />
 */
function AlertTitle({ className, ...props }: AlertTitleProps) {
  return (
    <div
      data-slot="alert-title"
      className={cn("font-medium leading-tight", className)}
      {...props}
    />
  );
}

/** Props accepted by `AlertDescription`. */
export type AlertDescriptionProps = React.ComponentPropsWithRef<"div">;

/** `AlertDescription` — the supporting body text under the title.
 *
 * @example
 * <AlertDescription />
 */
function AlertDescription({ className, ...props }: AlertDescriptionProps) {
  return (
    <div
      data-slot="alert-description"
      className={cn(
        "text-base leading-relaxed [&_p:not(:last-child)]:mb-2",
        className,
      )}
      {...props}
    />
  );
}

/** Props accepted by `AlertActions`. */
export type AlertActionsProps = React.ComponentPropsWithRef<"div">;

/** `AlertActions` — a row of action controls below the description.
 *
 * @example
 * <AlertActions />
 */
function AlertActions({ className, ...props }: AlertActionsProps) {
  return (
    <div
      data-slot="alert-actions"
      className={cn("mt-2 flex flex-wrap items-center gap-2", className)}
      {...props}
    />
  );
}

export { Alert, AlertTitle, AlertDescription, AlertActions };

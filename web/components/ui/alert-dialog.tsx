"use client";

import * as React from "react";
import { AlertDialog as BaseAlertDialog } from "@base-ui/react/alert-dialog";
import { cn } from "@vegastack/design";
import { useInternalThemeScope } from "@vegastack/design/theme-scope";
import { Button, type ButtonAppearance } from "@/components/ui/button";
import { useModalInert } from "@/components/ui/use-modal-inert";

/* ------------------------------------------------------------------------------------------------
 * AlertDialog — a modal confirmation dialog built on Base UI's AlertDialog. Exported FLAT
 * (shadcn-style): `AlertDialog` (=Root), `AlertDialogTrigger`, `AlertDialogContent` (composes
 * Portal+Backdrop+Viewport+Popup with enter/exit transitions), `AlertDialogHeader`,
 * `AlertDialogFooter`, `AlertDialogTitle`, `AlertDialogDescription`, `AlertDialogAction` (the
 * confirm button), and `AlertDialogCancel` (the cancel button).
 *
 * Unlike `Dialog`, an AlertDialog is intentionally NOT dismissable by clicking the backdrop — Base
 * UI's AlertDialog disables pointer dismissal so the user must pick Cancel, press Escape (cancel),
 * or choose the confirm Action. Reach for it for destructive/irreversible confirmations ("Delete
 * project", "Discard changes"); for everything else use `Dialog`.
 *
 * Enter/exit animate via Base UI's `data-starting-style`/`data-ending-style` data attributes +
 * token-duration transitions.
 * ----------------------------------------------------------------------------------------------*/

/**
 * `AlertDialog` — the root, controls open/close state. Doesn't render an element itself;
 * compose `AlertDialogTrigger` + `AlertDialogContent` inside it. Always modal (focus trapped,
 * page scroll locked), disables pointer/backdrop dismissal, and treats Escape as a cancel request.
 *
 * @example
 * <AlertDialog>
 *   <AlertDialogTrigger render={<Button variant="outline" tone="destructive">Delete</Button>} />
 *   <AlertDialogContent>
 *     <AlertDialogHeader>
 *       <AlertDialogTitle>Delete project</AlertDialogTitle>
 *       <AlertDialogDescription>This action cannot be undone.</AlertDialogDescription>
 *     </AlertDialogHeader>
 *     <AlertDialogFooter>
 *       <AlertDialogCancel>Cancel</AlertDialogCancel>
 *       <AlertDialogAction intent="destructive" onClick={handleDelete}>Delete</AlertDialogAction>
 *     </AlertDialogFooter>
 *   </AlertDialogContent>
 * </AlertDialog>
 */
export type AlertDialogProps = React.ComponentProps<
  typeof BaseAlertDialog.Root
>;

/** `AlertDialog` root; controls confirmation-dialog open state and modality.
 *
 * @example
 * <AlertDialog />
 */
export function AlertDialog(props: AlertDialogProps) {
  return <BaseAlertDialog.Root {...props} />;
}

/** Props accepted by `AlertDialogTrigger`. */
export type AlertDialogTriggerProps = React.ComponentProps<
  typeof BaseAlertDialog.Trigger
>;

/**
 * `AlertDialogTrigger` — the control that opens the dialog. Renders a `<button>`;
 * pass `render` to compose it with a `Button` or any other action element.

 *
 * @example
 * <AlertDialogTrigger />
 */
export function AlertDialogTrigger({
  className,
  ...props
}: AlertDialogTriggerProps) {
  return (
    <BaseAlertDialog.Trigger
      data-slot="alert-dialog-trigger"
      className={className}
      {...props}
    />
  );
}

/**
 * Intent of the confirmation — sets the tone of the dialog (carried onto `AlertDialogAction`
 * for its confirm-button tint). Mirrors the semantic-button intents.
 * - `default` — neutral, primary confirmation.
 * - `destructive` — dangerous/irreversible (delete, remove).
 * - `success` — positive confirmation (keep, confirm).
 * - `warning` — cautionary action.
 */
export type AlertDialogIntent =
  "default" | "destructive" | "success" | "warning";

/**
 * Props accepted by `AlertDialogContent`.
 *
 * There is deliberately no `intent` here. It used to write a `data-intent` hint and nothing else,
 * while the confirm button's tint was set separately on `AlertDialogAction` — two props for one
 * concept, one of them inert (audit B3-08). `AlertDialogAction intent` is the single owner.
 */
export type AlertDialogContentProps = React.ComponentProps<
  typeof BaseAlertDialog.Popup
>;

/**
 * `AlertDialogContent` — the centered popup. Composes Base UI's `Portal` + `Backdrop` + `Viewport`
 * + `Popup`, animates enter/exit, and traps focus. Drop `AlertDialogHeader`/`AlertDialogFooter`
 * and the title/description inside it. There is no top-right close button — the user must choose
 * `AlertDialogCancel`, press Escape, or choose `AlertDialogAction`.

 *
 * @example
 * <AlertDialogContent />
 */
export function AlertDialogContent({
  className,
  children,
  ref,
  ...props
}: AlertDialogContentProps) {
  const themeScope = useInternalThemeScope();
  const mergedRef = useModalInert<HTMLDivElement>({ ref });

  return (
    <BaseAlertDialog.Portal>
      <BaseAlertDialog.Backdrop
        data-slot="alert-dialog-backdrop"
        className={cn(
          themeScope,
          "fixed inset-0 z-(--z-overlay) bg-overlay",
          "transition-opacity duration-base ease-standard",
          "data-[starting-style]:opacity-0 data-[ending-style]:opacity-0",
        )}
      />
      <BaseAlertDialog.Viewport
        data-slot="alert-dialog-viewport"
        className={cn(
          themeScope,
          "fixed inset-0 z-(--z-overlay) flex items-center justify-center overflow-y-auto overscroll-contain p-4 outline-none",
        )}
      >
        <BaseAlertDialog.Popup
          ref={mergedRef}
          data-slot="alert-dialog-content"
          className={cn(
            themeScope,
            // `max-h-full`: the viewport is `fixed inset-0 p-4`, so its content box already IS the
            // available height (audit B3-09).
            "relative z-(--z-overlay) flex max-h-full w-full flex-col gap-4",
            // No `outline-none`: Base UI focuses the popup on open, so the centralized base.css
            // `:focus-visible` outline stays as the keyboard-focus indicator (register P0-02).
            // 24px modal-family padding tier (D14).
            "rounded-lg border border-border bg-popover p-6 text-base text-popover-foreground shadow-overlay",
            "sm:max-w-sm",
            // Enter/exit — scale + fade, token durations + standard easing.
            // D11: modals move at `base` (200ms).
            "origin-center transition-[opacity,transform] duration-base ease-standard",
            "data-[starting-style]:scale-95 data-[starting-style]:opacity-0",
            "data-[ending-style]:scale-95 data-[ending-style]:opacity-0",
            className,
          )}
          {...props}
        >
          {children}
        </BaseAlertDialog.Popup>
      </BaseAlertDialog.Viewport>
    </BaseAlertDialog.Portal>
  );
}

/** Props accepted by `AlertDialogHeader`. */
export type AlertDialogHeaderProps = React.ComponentProps<"div">;

/**
 * `AlertDialogHeader` — groups the title and description at the top of the content.

 *
 * @example
 * <AlertDialogHeader />
 */
export function AlertDialogHeader({
  className,
  ...props
}: AlertDialogHeaderProps) {
  return (
    <div
      data-slot="alert-dialog-header"
      className={cn("flex shrink-0 flex-col gap-1.5", className)}
      {...props}
    />
  );
}

/** Props accepted by `AlertDialogFooter`. */
export type AlertDialogFooterProps = React.ComponentProps<"div">;

/**
 * `AlertDialogFooter` — the action row at the bottom of the content. Stacks (reversed) on
 * narrow screens, becomes an end-aligned row from the `sm` breakpoint up. Place
 * `AlertDialogCancel` then `AlertDialogAction` inside it.

 *
 * @example
 * <AlertDialogFooter />
 */
export function AlertDialogFooter({
  className,
  ...props
}: AlertDialogFooterProps) {
  return (
    <div
      data-slot="alert-dialog-footer"
      className={cn(
        "flex shrink-0 flex-col-reverse gap-2 sm:flex-row sm:justify-end",
        className,
      )}
      {...props}
    />
  );
}

/** Props accepted by `AlertDialogTitle`. */
export type AlertDialogTitleProps = React.ComponentProps<
  typeof BaseAlertDialog.Title
>;

/**
 * `AlertDialogTitle` — the dialog's accessible name. Renders an `<h2>`; Base UI wires it to the
 * popup via `aria-labelledby`. Always include one.

 *
 * @example
 * <AlertDialogTitle />
 */
export function AlertDialogTitle({
  className,
  ...props
}: AlertDialogTitleProps) {
  return (
    <BaseAlertDialog.Title
      data-slot="alert-dialog-title"
      className={cn("text-h4 text-foreground", className)}
      {...props}
    />
  );
}

/** Props accepted by `AlertDialogDescription`. */
export type AlertDialogDescriptionProps = React.ComponentProps<
  typeof BaseAlertDialog.Description
>;

/**
 * `AlertDialogDescription` — supporting text under the title. Renders a `<p>`; Base UI wires it
 * to the popup via `aria-describedby`.

 *
 * @example
 * <AlertDialogDescription />
 */
export function AlertDialogDescription({
  className,
  ...props
}: AlertDialogDescriptionProps) {
  return (
    <BaseAlertDialog.Description
      data-slot="alert-dialog-description"
      className={cn(
        "text-base leading-relaxed text-muted-foreground",
        className,
      )}
      {...props}
    />
  );
}

/**
 * Maps the confirm-button `intent` onto the shared Button matrix, so `AlertDialogAction` stays in
 * lockstep with the button styling (focus, sizing, hover) instead of duplicating it. A destructive
 * confirm is an OUTLINE, never a solid red button — the doctrine's one forbidden cell.
 */
const ACTION_INTENT_APPEARANCE: Record<AlertDialogIntent, ButtonAppearance> = {
  default: { variant: "solid" },
  destructive: { variant: "outline", tone: "destructive" },
  success: { variant: "outline", tone: "success" },
  warning: { variant: "outline", tone: "warning" },
};

/** Props accepted by `AlertDialogAction`. */
export interface AlertDialogActionProps extends React.ComponentProps<
  typeof BaseAlertDialog.Close
> {
  /**
   * Semantic tint of the confirm button — the single owner of the confirmation's severity.
   * @default "default"
   */
  intent?: AlertDialogIntent;
  /**
   * Shows a spinner and marks the confirm button busy while an async confirm is pending — wired
   * straight through to the underlying {@link Button}'s `loading` prop (spinner, `aria-busy`, and a
   * real `disabled` control). Because the rendered button becomes genuinely `disabled`, a click
   * while `loading` never reaches Base UI's `Close` click handler, so the dialog stays open until
   * you flip `loading` back to `false` (typically in the `onClick` handler's `finally`).
   * @default false
   */
  loading?: boolean;
}

/**
 * `AlertDialogAction` — the confirm button. Closes the dialog when clicked (Base UI `Close`), so
 * wire your confirm work through `onClick`. Composes the shared {@link Button} with the `intent`
 * tint (default/destructive/success/warning) and, when `loading` is set, its spinner/busy/disabled
 * state — use it for async confirms (e.g. `onClick={async () => { setLoading(true); await
 * doDelete(); setLoading(false); }}`). Pass `render` to swap the element.

 *
 * @example
 * <AlertDialogAction />
 */
export function AlertDialogAction({
  className,
  intent = "default",
  loading = false,
  ...props
}: AlertDialogActionProps) {
  return (
    <BaseAlertDialog.Close
      className={className}
      render={
        <Button
          {...ACTION_INTENT_APPEARANCE[intent]}
          data-slot="alert-dialog-action"
          data-intent={intent}
          loading={loading}
        />
      }
      {...props}
    />
  );
}

/** Props accepted by `AlertDialogCancel`. */
export type AlertDialogCancelProps = React.ComponentProps<
  typeof BaseAlertDialog.Close
>;

/**
 * `AlertDialogCancel` — the cancel button. Closes the dialog without confirming (Base UI
 * `Close`). Composes the shared {@link Button} `outline` variant. Pass `render` to swap the element.

 *
 * @example
 * <AlertDialogCancel />
 */
export function AlertDialogCancel({
  className,
  ...props
}: AlertDialogCancelProps) {
  return (
    <BaseAlertDialog.Close
      className={className}
      render={<Button variant="outline" data-slot="alert-dialog-cancel" />}
      {...props}
    />
  );
}

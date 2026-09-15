"use client";

import * as React from "react";
import { cn } from "@vegastack/design";
import { Button } from "@/components/ui/button";
import { StatusIcon } from "@/components/ui/status-icon";

/* ---
`Stepper` exists because a bounded linear process — onboarding, wizards, checkout,
imports — has no correct substrate in the roster. `Tabs` is the tempting wrong answer:
`role="tab"` announces "tab 2 of 6" and implies free navigation between peers, which
actively misleads assistive tech about a flow where step 4 may be unreachable until
step 3 validates. The correct semantics are an ordered list with `aria-current="step"`,
and that is what this ships.

What the existing parts could not give (and why documenting a recipe was rejected):
- focus management on step change — focus moves to the NEW step's label, not the first
  field, or a screen-reader user hears nothing;
- `aria-current="step"` on a correctly labelled `<ol>`;
- an advance-gating contract (`blockedReason`) whose reason is rendered AND announced,
  and wireable to the host's Next button via `aria-describedby`;
- the **error** state — the one every hand-rolled stepper forgets;
- one set of semantics across both orientations.

Deliberately NOT done here:
- No Back/Next buttons and no step bodies. Gating is the host's logic and the form is
  the host's form; this component *communicates* the process. The multi-step-form
  assembly (stepper + Field + validation) is a Guides page.
- No compact segments voice. Where a full step list is too heavy, that is
  `ProgressIndicator segments` — a different component on purpose.
- No auto-derived states. The host names each step's state explicitly; deriving
  complete/upcoming from an index would bake in "linear and always forward", which
  imports with failed steps are not.
--- */

/** The state of one step. `error` is a first-class state, not a decoration. */
export type StepperStepState = "complete" | "current" | "upcoming" | "error";

/** One step in the process. */
export interface StepperStep {
  /** Stable identifier — selection events return it. */
  id: string;
  /** Visible step label. Receives focus when the step becomes current. */
  label: string;
  /** Optional secondary line under the label.
   * @default undefined
   */
  description?: string;
  /** The step's state. Exactly one step should be `current`. */
  state: StepperStepState;
  /**
   * Marks a step unreachable even in navigable mode (e.g. gated by a plan).
   * @default false
   */
  disabled?: boolean;
}

/** Maps step state onto `StatusIcon`'s vocabulary — a 1:1 correspondence. */
const STATE_ICON: Record<
  StepperStepState,
  "done" | "progress" | "todo" | "blocked"
> = {
  complete: "done",
  current: "progress",
  upcoming: "todo",
  error: "blocked",
};

/** Sr-only state text so state is never carried by the icon colour alone. */
const STATE_TEXT: Record<StepperStepState, string> = {
  complete: "Completed",
  current: "Current step",
  upcoming: "Not started",
  error: "Needs attention",
};

/** Props accepted by `Stepper`. */
export interface StepperProps extends Omit<
  React.ComponentPropsWithRef<"ol">,
  "children"
> {
  /** The ordered steps. Exactly one should carry `state: "current"`. */
  steps: StepperStep[];
  /**
   * Layout direction. Both orientations keep the same DOM and reading order.
   * @default "horizontal"
   */
  orientation?: "horizontal" | "vertical";
  /**
   * Navigable mode: completed steps render as real buttons that fire
   * `onStepSelect`. In linear mode (the default) no step is interactive —
   * movement belongs to the host's Back/Next controls.
   * @default false
   */
  navigable?: boolean;
  /**
   * Fired in navigable mode when a completed step is activated.

   * @default undefined
   */
  onStepSelect?: (id: string) => void;
  /**
   * Why the process cannot advance right now ("Select at least one column").
   * Rendered against the current step and announced politely. Gating itself is
   * the host's logic — this communicates the block.

   * @default undefined
   */
  blockedReason?: string;
  /**
   * Id for the blocked-reason element, so the host can wire
   * `aria-describedby={blockedReasonId}` on its own Next button. Auto-generated
   * when omitted.

   * @default undefined
   */
  blockedReasonId?: string;
  /**
   * Accessible name for the process.
   * @default "Progress"
   */
  "aria-label"?: string;
}

/**
 * `Stepper` — a bounded linear process as an ordered list:
 * complete / current / upcoming / **error** states (mapped 1:1 onto
 * `StatusIcon`'s vocabulary), `aria-current="step"`, horizontal or vertical
 * orientation, an advance-gating message contract, and focus moved to the new
 * step's label whenever the current step changes (never on first mount).
 *
 * **Not `Tabs`** — `role="tab"` implies free navigation and misleads assistive
 * tech in a linear flow. **Not `Segmented`** — that is radio semantics for view
 * switching.
 *
 * @example
 * <Stepper
 *   aria-label="Import"
 *   steps={[
 *     { id: "upload", label: "Upload file", state: "complete" },
 *     { id: "map", label: "Map columns", state: "current" },
 *     { id: "review", label: "Review", state: "upcoming" },
 *   ]}
 *   blockedReason={mapped ? undefined : "Map every required column to continue"}
 * />
 */
export function Stepper({
  steps,
  orientation = "horizontal",
  navigable = false,
  onStepSelect,
  blockedReason,
  blockedReasonId,
  "aria-label": ariaLabel = "Progress",
  className,
  ref,
  ...props
}: StepperProps) {
  const generatedReasonId = React.useId();
  const reasonId = blockedReasonId ?? generatedReasonId;
  const currentId = steps.find((step) => step.state === "current")?.id;
  const labelRefs = React.useRef(new Map<string, HTMLElement>());

  // Focus follows the process: when the CURRENT step changes (a live
  // transition, never the initial render), move focus to the new step's label
  // so keyboard and screen-reader users land on "where am I now" — not on the
  // first form field and not at the top of the page.
  const previousCurrentId = React.useRef<string | undefined>(currentId);
  React.useEffect(() => {
    if (
      previousCurrentId.current !== undefined &&
      currentId !== undefined &&
      previousCurrentId.current !== currentId
    ) {
      labelRefs.current.get(currentId)?.focus();
    }
    previousCurrentId.current = currentId;
  }, [currentId]);

  return (
    <ol
      ref={ref}
      data-slot="stepper"
      data-orientation={orientation}
      aria-label={ariaLabel}
      className={cn(
        "flex list-none",
        orientation === "horizontal"
          ? "w-full flex-row items-start"
          : "flex-col",
        className,
      )}
      {...props}
    >
      {steps.map((step, index) => {
        const isCurrent = step.state === "current";
        const isLast = index === steps.length - 1;
        // Completed AND error steps are revisitable in navigable mode — a
        // failed step is exactly the one the user needs to get back to.
        const selectable =
          navigable &&
          (step.state === "complete" || step.state === "error") &&
          !step.disabled;

        const labelContent = (
          <>
            <span className="min-w-0 truncate">{step.label}</span>
            <span className="sr-only">{STATE_TEXT[step.state]}</span>
          </>
        );

        return (
          <li
            key={step.id}
            data-slot="stepper-step"
            data-state={step.state}
            data-disabled={step.disabled ? "" : undefined}
            aria-current={isCurrent ? "step" : undefined}
            className={cn(
              "flex min-w-0",
              orientation === "horizontal"
                ? "flex-1 flex-col items-start gap-1 last:flex-none"
                : "flex-row gap-3",
            )}
          >
            {/* Node + connector rail. The connector is decorative geometry. */}
            <span
              data-slot="stepper-node"
              className={cn(
                "flex shrink-0 items-center",
                orientation === "horizontal"
                  ? "w-full flex-row gap-2"
                  : "flex-col gap-1 self-stretch",
              )}
            >
              <StatusIcon
                status={STATE_ICON[step.state]}
                size="sm"
                label=""
                className={cn(
                  // The stepper's progress glyph must not spin — "current" is a
                  // position, not activity.
                  step.state === "current" && "animate-none",
                )}
              />
              {!isLast ? (
                <span
                  aria-hidden
                  data-slot="stepper-connector"
                  className={cn(
                    "bg-border",
                    orientation === "horizontal"
                      ? "h-px min-w-6 flex-1"
                      : "mx-auto min-h-4 w-px flex-1",
                  )}
                />
              ) : null}
            </span>

            <span
              data-slot="stepper-content"
              className={cn(
                "flex min-w-0 flex-col",
                orientation === "horizontal" && "w-full pe-4",
              )}
            >
              {selectable ? (
                <Button
                  variant="link"
                  tone="neutral"
                  size="md"
                  ref={(node: HTMLElement | null) => {
                    if (node) labelRefs.current.set(step.id, node);
                    else labelRefs.current.delete(step.id);
                  }}
                  data-slot="stepper-label"
                  onClick={() => onStepSelect?.(step.id)}
                  // A navigable step label IS a link-shaped control, so it takes the `link`
                  // variant rather than a `ghost` Button reshaped into inline text by stripping
                  // its height and padding (B7-09). `size="md"` keeps the label at the same
                  // `text-base` the static label uses; nothing about the control box is
                  // overridden here, only its alignment.
                  className={cn(
                    "min-w-0 justify-start gap-1",
                    orientation === "horizontal" && "w-full",
                  )}
                >
                  {labelContent}
                </Button>
              ) : (
                <span
                  ref={(node) => {
                    if (node) labelRefs.current.set(step.id, node);
                    else labelRefs.current.delete(step.id);
                  }}
                  data-slot="stepper-label"
                  // Focus target when the step becomes current — not a tab stop.
                  tabIndex={isCurrent ? -1 : undefined}
                  className={cn(
                    "inline-flex min-w-0 items-center gap-1 rounded-sm text-base",
                    orientation === "horizontal" && "w-full",
                    isCurrent || step.state === "error"
                      ? "font-medium text-foreground"
                      : "text-muted-foreground",
                    step.disabled && "opacity-(--opacity-dim)",
                  )}
                >
                  {labelContent}
                </span>
              )}
              {step.description ? (
                <span
                  data-slot="stepper-description"
                  className="min-w-0 truncate text-sm text-muted-foreground"
                >
                  {step.description}
                </span>
              ) : null}
              {isCurrent ? (
                // Always mounted while the step is current: a live region must
                // exist in the a11y tree BEFORE its content changes, or the
                // idle → blocked transition announces nothing.
                <span
                  id={reasonId}
                  data-slot="stepper-blocked-reason"
                  role="status"
                  aria-live="polite"
                  className={cn(
                    "mt-0.5 text-sm text-warning-text",
                    !blockedReason && "sr-only",
                  )}
                >
                  {blockedReason}
                </span>
              ) : null}
            </span>
          </li>
        );
      })}
    </ol>
  );
}

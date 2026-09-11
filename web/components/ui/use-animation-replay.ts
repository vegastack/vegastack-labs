"use client";

import * as React from "react";

/**
 * MECHANISM (locked, CX-13 / Phase M investigation) — **class-toggle + `animationend`
 * cleanup**, not key-remount.
 *
 * Two mechanisms were evaluated:
 * 1. **Key-remount** — bump a `key`, let React tear down and recreate the element so its
 *    mount-triggered CSS animation (`motion-pop-in`, `motion-enter-up`, `motion-shake`, …)
 *    plays again. Simple, but remounting an element blurs it if it (or a descendant) held
 *    focus, and resets any native input state (value/caret/selection) that isn't otherwise
 *    controlled. A form control that shakes because it just became invalid is exactly the
 *    element most likely to be focused at that moment — key-remount is unusable there.
 *    Wrapping the *ancestor* instead doesn't help: changing a parent's `key` unmounts its
 *    entire subtree, including the focused input inside it.
 * 2. **Class-toggle** — add the animation class, listen for `animationend`, remove it. The
 *    element's identity never changes, so focus, value, and selection are untouched. Restarting
 *    mid-animation (e.g. a second failed submit while already invalid) needs an explicit "off,
 *    then on again next frame" cycle — CSS only replays an `animation` when it newly starts
 *    applying, so toggling the class off and back on is what re-triggers it.
 *
 * Class-toggle is the only mechanism that passes a focus-preservation test (focus an `<input>`,
 * trigger a replay, assert `document.activeElement`/value/selection are unchanged — see
 * `use-animation-replay.test.tsx`), so it is the ONE mechanism this hook ships, used uniformly
 * for every consumer (form controls and non-form elements alike) rather than mixing two
 * mechanisms depending on element type.
 */
export interface UseAnimationReplayResult {
  /**
   * Whether the animation class is currently applied (the animation is mid-playback).
   */
  isActive: boolean;
  /**
   * The animation class name while `isActive`, or `undefined` at rest. Merge onto the
   * animated element's `className` (e.g. `cn(baseClasses, replay.className)`).
   */
  className: string | undefined;
  /**
   * Spread onto the animated element as `onAnimationEnd`. Clears the animation class once the
   * CSS animation finishes playing, so the element returns to its rest state and a later
   * `replay()` call starts a fresh run instead of no-op'ing against an already-applied class.
   * Ignores animations bubbling up from descendants (e.g. an icon's own animation) by checking
   * `event.target === event.currentTarget`.
   */
  onAnimationEnd: (event: React.AnimationEvent) => void;
  /**
   * (Re)play the animation. Safe to call while a previous run is still playing — the class is
   * removed and re-applied one animation frame later, which restarts the CSS animation cleanly
   * (an interruption mid-shake doesn't "stick" in a half-played or permanently-active state).
   */
  replay: () => void;
}

/**
 * `useAnimationReplay` — the system-wide primitive for re-triggering a mount-style CSS
 * animation (`motion-pop-in`, `motion-enter-up`, `motion-shake`, `motion-check-draw`, …) on
 * demand, without remounting the element. See the module doc above for why class-toggle (not
 * key-remount) is the chosen mechanism.
 *
 * This is a low-level building block: it only knows how to play `animationClassName` once per
 * `replay()` call. Pass whichever token-sanctioned `motion-*` utility class you want to replay.
 * For the specific "shake a form control when it becomes invalid" pattern, use
 * {@link useShakeOnInvalid}, which wraps this hook with invalid-transition detection.
 *
 * @param animationClassName - The `motion-*` utility class to toggle (e.g. `'motion-shake'`).
 *
 * @example
 * function SuccessIcon() {
 *   const replay = useAnimationReplay('motion-pop-in');
 *   return (
 *     <button onClick={replay.replay}>
 *       <Check
 *         className={cn('size-(--icon-default)', replay.className)}
 *         onAnimationEnd={replay.onAnimationEnd}
 *       />
 *     </button>
 *   );
 * }
 */
export function useAnimationReplay(
  animationClassName: string,
): UseAnimationReplayResult {
  const [isActive, setIsActive] = React.useState(false);
  const rafRef = React.useRef<number | null>(null);

  // Unmount cleanup — don't leak a pending rAF into a torn-down component.
  React.useEffect(() => {
    return () => {
      if (rafRef.current != null) cancelAnimationFrame(rafRef.current);
    };
  }, []);

  const replay = React.useCallback(() => {
    if (rafRef.current != null) {
      cancelAnimationFrame(rafRef.current);
      rafRef.current = null;
    }
    // Turn the class off first (no-op if it was already off) so the *next* frame's re-application
    // is always a fresh "start applying the animation" transition — the only thing that makes a CSS
    // `animation` (re)play. Doing this synchronously (skipping the frame) risks React batching the
    // off+on into a single commit, which the browser would never see as two separate states.
    setIsActive(false);
    rafRef.current = requestAnimationFrame(() => {
      rafRef.current = null;
      setIsActive(true);
    });
  }, []);

  const onAnimationEnd = React.useCallback((event: React.AnimationEvent) => {
    if (event.target !== event.currentTarget) return;
    setIsActive(false);
  }, []);

  return {
    isActive,
    className: isActive ? animationClassName : undefined,
    onAnimationEnd,
    replay,
  };
}

/**
 * The repeated-failure re-shake signal: any value works — a submit-attempt counter, a new error
 * string, an object identity — whatever is convenient at the call site; changes are detected by
 * `===`. Named (rather than an inline `unknown`) so `shakeSignal` renders as a meaningful type in
 * docs API tables across every consumer (Input, Checkbox, RadioGroup, OTPInput, PasswordInput).
 */
export type ShakeSignal = unknown;

export interface UseShakeOnInvalidOptions {
  /**
   * Bump this to a new value (e.g. increment a submit-attempt counter) to force a re-shake
   * while the control is ALREADY invalid — the transition-detection below only fires once per
   * false→true edge, so a second failed submission against the same still-invalid control needs
   * this explicit signal. Ignored while the control is currently valid (only fires when already
   * invalid, matching "shake again on repeated failure" rather than "shake because it became
   * invalid" — that case is handled automatically). Compare by `===`; any changed value re-shakes
   * (a counter, a new error string, an object identity — whatever is convenient at the call site).
   */
  shakeSignal?: ShakeSignal;
}

export interface UseShakeOnInvalidResult {
  /**
   * Ref CALLBACK — attach to the DOM element that carries `aria-invalid`/`data-invalid` (often
   * the same element you animate, but doesn't have to be). A `MutationObserver` watches exactly
   * those two attributes on this node.
   *
   * Why an attribute observer instead of reading an `invalid`/`aria-invalid` PROP: Base UI's
   * Field context wires validity onto form controls (Input — which IS `Field.Control` under the
   * hood, Checkbox, Radio, OTPField all self-register) by writing `aria-invalid`/`data-invalid`
   * straight onto the rendered DOM node — it never round-trips back through this wrapper
   * component's own React props. A component nested in `<Field>` (the documented, common
   * composition — `<Field error="…"><Input /></Field>`) never receives an `aria-invalid` PROP at
   * all; the attribute only exists on the real element after Base UI renders it. Observing the
   * DOM attribute directly is therefore the only mechanism that works for both that case and the
   * fully-standalone case (`<Input aria-invalid />`), uniformly, without the component needing to
   * know which one it's in.
   */
  invalidRef: React.RefCallback<HTMLElement>;
  /** Animation class while shaking, or `undefined` at rest — spread onto the animated element. */
  className: string | undefined;
  /** Spread onto the animated element as `onAnimationEnd`. */
  onAnimationEnd: (event: React.AnimationEvent) => void;
  /** Whether the shake animation is currently playing. */
  isShaking: boolean;
}

function readInvalidAttribute(element: HTMLElement): boolean {
  return (
    element.getAttribute("aria-invalid") === "true" ||
    element.hasAttribute("data-invalid")
  );
}

/**
 * `useShakeOnInvalid` — auto-plays `motion-shake` once when the observed element's
 * `aria-invalid`/`data-invalid` attributes transition from absent/false to present/true (built on
 * {@link useAnimationReplay}; see that hook's doc for the class-toggle-not-key-remount rationale).
 *
 * Does NOT shake for an element that is already invalid when it first mounts — only a live
 * false→true transition triggers it, so a form pre-rendered with server-side validation errors
 * doesn't shake on first paint (a mount-time shake would look like unprompted, undirected motion;
 * the point of this animation is to react to something the user just did).
 *
 * For "shake again on a second failed submission" while the control is STILL invalid (the
 * false→true edge only fires once), pass a changing {@link UseShakeOnInvalidOptions.shakeSignal} —
 * bump a submit-attempt counter each time validation re-runs and fails.
 *
 * 'use client' (this hook uses state, refs, and a `MutationObserver`) — consumers that wire this
 * in unconditionally become client components. That's an intentional, load-bearing cost of
 * shipping real auto-shake-on-invalid behavior; components that don't need it stay server-safe.
 *
 * @example
 * function MyField({ invalid, shakeAttempt, ...props }) {
 *   const shake = useShakeOnInvalid({ shakeSignal: shakeAttempt });
 *   const ref = mergeRefs(props.ref, shake.invalidRef);
 *   return (
 *     <input
 *       ref={ref}
 *       aria-invalid={invalid}
 *       className={cn('rounded-md border', shake.className)}
 *       onAnimationEnd={shake.onAnimationEnd}
 *       {...props}
 *     />
 *   );
 * }
 */
export function useShakeOnInvalid(
  options: UseShakeOnInvalidOptions = {},
): UseShakeOnInvalidResult {
  const { shakeSignal } = options;
  const { className, onAnimationEnd, replay, isActive } =
    useAnimationReplay("motion-shake");

  const elementRef = React.useRef<HTMLElement | null>(null);
  const observerRef = React.useRef<MutationObserver | null>(null);
  const wasInvalidRef = React.useRef(false);
  const replayRef = React.useRef(replay);
  replayRef.current = replay;

  const invalidRef = React.useCallback((element: HTMLElement | null) => {
    observerRef.current?.disconnect();
    observerRef.current = null;
    elementRef.current = element;
    if (element == null) return;

    // Baseline only — establish the current invalid-ness WITHOUT shaking, so a control that's
    // already invalid at mount doesn't shake on first paint (see JSDoc above).
    wasInvalidRef.current = readInvalidAttribute(element);

    const observer = new MutationObserver(() => {
      const target = elementRef.current;
      if (!target) return;
      const invalid = readInvalidAttribute(target);
      if (invalid && !wasInvalidRef.current) {
        replayRef.current();
      }
      wasInvalidRef.current = invalid;
    });
    observer.observe(element, {
      attributes: true,
      attributeFilter: ["aria-invalid", "data-invalid"],
    });
    observerRef.current = observer;
  }, []);

  React.useEffect(() => {
    return () => observerRef.current?.disconnect();
  }, []);

  // Repeated-failure signal: only re-shakes while ALREADY invalid (see JSDoc on shakeSignal).
  const lastSignalRef = React.useRef(shakeSignal);
  React.useEffect(() => {
    if (shakeSignal === undefined || shakeSignal === lastSignalRef.current)
      return;
    lastSignalRef.current = shakeSignal;
    if (wasInvalidRef.current) replay();
  }, [shakeSignal, replay]);

  return { invalidRef, className, onAnimationEnd, isShaking: isActive };
}

/**
 * Combine multiple refs (a forwarded `ref` prop plus this file's `invalidRef`, typically) into
 * one ref callback so both land on the same DOM node. Skips `null`/`undefined` entries. Not
 * memoized internally — wrap the CALL in `React.useCallback`/`React.useMemo` at the call site if
 * the inputs are stable, to avoid detaching/reattaching refs on every render.
 */
export function mergeRefs<T>(
  ...refs: Array<React.Ref<T> | null | undefined>
): React.RefCallback<T> {
  return (node: T | null) => {
    for (const ref of refs) {
      if (ref == null) continue;
      if (typeof ref === "function") {
        ref(node);
      } else {
        (ref as React.RefObject<T | null>).current = node;
      }
    }
  };
}

"use client";

import * as React from "react";
import { mergeRefs } from "@vegastack/design";

const BASE_UI_INERT = "[data-base-ui-inert]";
// A region-level live surface (for example ToastViewport) is an independently reachable
// notification landmark. Control-local status announcers stay inside the inert background.
const LIVE_REGION = '[aria-live][role="region"]';

interface InertOwnership {
  owners: number;
  original: boolean;
}

// One ownership table for every modal family importing this hook. Nested or overlapping modals may
// acquire the same outside root; its original value is restored only after the final owner leaves.
const inertOwnership = new WeakMap<HTMLElement, InertOwnership>();

function acquireInert(element: HTMLElement) {
  const current = inertOwnership.get(element);
  if (current) {
    current.owners += 1;
  } else {
    inertOwnership.set(element, { owners: 1, original: element.inert });
  }
  element.inert = true;
}

function releaseInert(element: HTMLElement) {
  const current = inertOwnership.get(element);
  if (!current) return;
  current.owners -= 1;
  if (current.owners > 0) return;
  element.inert = current.original;
  inertOwnership.delete(element);
}

function inertTargetsForMarkedRoot(element: HTMLElement) {
  if (element.matches(LIVE_REGION)) return [];
  if (!element.querySelector(LIVE_REGION)) return [element];

  const targets: HTMLElement[] = [];
  const visit = (parent: HTMLElement) => {
    for (const child of Array.from(parent.children)) {
      if (!(child instanceof HTMLElement)) continue;
      if (child.matches(LIVE_REGION)) continue;
      if (child.querySelector(LIVE_REGION)) {
        visit(child);
      } else {
        targets.push(child);
      }
    }
  };
  visit(element);
  return targets;
}

/** Options accepted by `useModalInert`. */
export interface UseModalInertOptions<T extends HTMLElement> {
  /** Caller ref merged with the hook's popup lifecycle ref.
   * @default undefined
   */
  ref?: React.Ref<T>;
  /** Whether this popup has full modal semantics and should mirror native inert.
   * @default true
   */
  enabled?: boolean;
}

/**
 * `useModalInert` — mirror Base UI's live `data-base-ui-inert` modal-stack markers to the native
 * `inert` property. Base UI owns WHICH subtrees are outside; this hook only makes that decision
 * effective for sequential keyboard focus when a focus guard transiently hands focus to `<body>`.
 * Ownership is reference-counted across Dialog, AlertDialog and Sheet, and each element's prior
 * inert value is restored after its final modal owner releases it. Region-level live surfaces
 * preserve Base UI's accessibility exception so portaled notifications remain announced and
 * interactive without making control-local announcers punch holes through the modal boundary.
 *
 * Pass `enabled: false` for non-modal roots and `modal="trap-focus"`: native inert would also block
 * outside pointer interaction, which those modes explicitly preserve.
 *
 * @example
 * const popupRef = useModalInert<HTMLDivElement>({ ref, enabled: modal === true });
 * return <BaseDialog.Popup ref={popupRef} />;
 */
export function useModalInert<T extends HTMLElement>({
  ref,
  enabled = true,
}: UseModalInertOptions<T> = {}): React.RefCallback<T> {
  const [popup, setPopup] = React.useState<T | null>(null);
  const capturePopup = React.useCallback((element: T | null) => {
    setPopup(element);
  }, []);
  const mergedRef = React.useMemo(
    () => mergeRefs(ref, capturePopup),
    [capturePopup, ref],
  );

  React.useLayoutEffect(() => {
    if (!popup || !enabled) return;
    const portal = popup.closest<HTMLElement>("[data-base-ui-portal]");
    if (!portal) return;

    const acquired = new Set<HTMLElement>();
    const sync = () => {
      const markedRoots = Array.from(
        document.querySelectorAll<HTMLElement>(BASE_UI_INERT),
      ).filter(
        (element) =>
          element !== portal &&
          !portal.contains(element) &&
          !element.contains(portal),
      );
      const marked = new Set(markedRoots.flatMap(inertTargetsForMarkedRoot));
      for (const element of acquired) {
        if (marked.has(element)) continue;
        releaseInert(element);
        acquired.delete(element);
      }
      for (const element of marked) {
        if (acquired.has(element)) continue;
        acquireInert(element);
        acquired.add(element);
      }
    };

    sync();
    const observer = new MutationObserver(sync);
    observer.observe(document.body, {
      subtree: true,
      childList: true,
      attributes: true,
      attributeFilter: ["aria-live", "data-base-ui-inert", "role"],
    });
    return () => {
      observer.disconnect();
      for (const element of acquired) releaseInert(element);
    };
  }, [enabled, popup]);

  return mergedRef;
}

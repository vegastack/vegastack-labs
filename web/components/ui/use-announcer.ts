"use client";

import * as React from "react";
import { cn } from "@vegastack/design";

/* ---
`useAnnouncer` exists because the SAME twelve lines were written five times in this registry —
`editable-cell`, `chip-input`, `data-grid`, `use-drag-reorder` and `use-file-drop` each kept a
`{ text, seq }` state, an updater that incremented the counter alongside the text, and a
`<span role="status" aria-live="polite" aria-atomic><span key={seq}>` node, with the same comment
explaining the sequence counter (audit 2026-09-07, B5-05 / 04-cross-cutting §1). One hook, one
policy, one node per announcing component.

Two things the copies got right and this hook keeps:

- **The sequence counter is load-bearing.** Announcing the identical string twice in a row (a second
  rejected duplicate chip, a second failed save) is a same-value `setState`, which React bails out
  of — the DOM never mutates and assistive tech never re-announces. Keying an inner span by a
  monotonic sequence forces a real DOM replacement every time, so every announcement is spoken.
- **The region is mounted for the component's whole life.** A live region inserted into the DOM at
  the moment it has content is frequently NOT announced — the platform has to have been observing
  it. `Announcer` therefore renders an empty region from first paint and only ever swaps its child.

One thing they got wrong and this hook fixes: the copies held announcement state in the HOST
component, so every announcement re-rendered the entire DataGrid or Board. Here the state lives in a
per-hook store that only `Announcer` subscribes to, so an announcement re-renders one `<span>`.
`Announcer`'s identity is stable for the life of the hook (memoised on the store, which never
changes), which matters for the same reason the mount does: a component whose TYPE changed would be
unmounted and remounted, destroying the observed region on every announcement.

Deliberately NOT done here:
- No `assertive` mode. `role="alert"` is a separate policy decision per D23 (polite `status` by
  default; `alert` only for destructive/warning content rendered after mount) and belongs to the
  component that owns the message, not to a shared announcer.
- No queue or debounce. `aria-live="polite"` already queues at the platform level, and announcing
  the DESTINATION rather than every intermediate frame is the caller's job (`design.md`
  §Accessibility).
- No visible variant. Every consumer's region is `sr-only`; a visible status line is ordinary
  markup with its own `role="status"`.
--- */

/** The announcement snapshot: the text plus the counter that forces a DOM mutation. */
interface Announcement {
  text: string;
  seq: number;
}

/** The shared empty snapshot — identical on the server and on the first client render. */
const EMPTY: Announcement = { text: "", seq: 0 };

/** @internal The per-hook store `Announcer` subscribes to. */
interface AnnouncementStore {
  subscribe: (onStoreChange: () => void) => () => void;
  getSnapshot: () => Announcement;
  announce: (text: string) => void;
}

function createAnnouncementStore(): AnnouncementStore {
  let snapshot: Announcement = EMPTY;
  const listeners = new Set<() => void>();
  return {
    subscribe(onStoreChange) {
      listeners.add(onStoreChange);
      return () => {
        listeners.delete(onStoreChange);
      };
    },
    getSnapshot: () => snapshot,
    announce(text) {
      snapshot = { text, seq: snapshot.seq + 1 };
      for (const listener of listeners) listener();
    },
  };
}

const getServerSnapshot = (): Announcement => EMPTY;

/** Props accepted by the `Announcer` element returned by {@link useAnnouncer}. */
export interface AnnouncerProps extends React.ComponentPropsWithRef<"span"> {
  /**
   * Extra classes merged with `sr-only`. The region must stay visually hidden and
   * in the layout — `display: none` removes it from the accessibility tree.
   * @default undefined
   */
  className?: string;
}

function createAnnouncerComponent(
  store: AnnouncementStore,
): React.ComponentType<AnnouncerProps> {
  function Announcer({ className, children, ...props }: AnnouncerProps) {
    const announcement = React.useSyncExternalStore(
      store.subscribe,
      store.getSnapshot,
      getServerSnapshot,
    );
    return React.createElement(
      "span",
      {
        "data-slot": "announcer",
        role: "status",
        "aria-live": "polite",
        "aria-atomic": "true",
        className: cn("sr-only", className),
        ...props,
      },
      React.createElement("span", { key: announcement.seq }, announcement.text),
    );
  }
  Announcer.displayName = "Announcer";
  return Announcer;
}

/** What {@link useAnnouncer} returns. */
export interface UseAnnouncerResult {
  /**
   * Speak `text` politely. Safe to call with the same string twice in a row — the
   * region is re-keyed, so the repeat is announced rather than swallowed.
   */
  announce: (text: string) => void;
  /**
   * The live region. Render it ONCE, anywhere inside the component, for the
   * component's whole life. Stable across renders.
   */
  Announcer: React.ComponentType<AnnouncerProps>;
}

/**
 * `useAnnouncer` — the one polite live region. Returns `announce(text)` and an `Announcer`
 * component; render `<Announcer />` once and call `announce` whenever something happened that a
 * screen-reader user would otherwise miss (a row moved, a chip was rejected, a save failed).
 *
 * Announce the **destination**, never every intermediate frame: "Moved Design to position 3 of 7",
 * not one message per pointer move.
 *
 * @example
 * function ChipField() {
 *   const { announce, Announcer } = useAnnouncer();
 *   return (
 *     <div>
 *       <button onClick={() => announce("Duplicate entry ignored")}>Add</button>
 *       <Announcer />
 *     </div>
 *   );
 * }
 */
export function useAnnouncer(): UseAnnouncerResult {
  const storeRef = React.useRef<AnnouncementStore | null>(null);
  storeRef.current ??= createAnnouncementStore();
  const store = storeRef.current;

  const announce = React.useCallback(
    (text: string) => {
      store.announce(text);
    },
    [store],
  );
  const Announcer = React.useMemo(
    () => createAnnouncerComponent(store),
    [store],
  );

  return React.useMemo(() => ({ announce, Announcer }), [announce, Announcer]);
}

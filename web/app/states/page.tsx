import type { Metadata } from "next";
import { ConsoleShell } from "@/components/console-shell";
import { ConsoleState, type ConsoleStateKind } from "@/components/console-state";

export const metadata: Metadata = { title: "Foundation states" };

const states: Array<{ kind: ConsoleStateKind; title: string; description: string }> = [
  { kind: "loading", title: "Loading", description: "Example: waiting for an API response." },
  { kind: "empty", title: "Empty", description: "Example: an authorized collection has no records." },
  { kind: "error", title: "Error", description: "Example: a request failed without applying a change." },
  { kind: "unavailable", title: "Unavailable", description: "Example: the requested service could not be reached." },
];

export default function FoundationStatesPage() {
  return <ConsoleShell title="Foundation states"><p className="mb-6 text-sm text-muted-foreground">Design examples only. These cards do not describe your cluster or its connection.</p><div className="grid gap-4 md:grid-cols-2">{states.map(state => <ConsoleState key={state.kind} {...state} />)}</div></ConsoleShell>;
}

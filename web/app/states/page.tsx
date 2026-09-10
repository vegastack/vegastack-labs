import { ConsoleShell } from "@/components/console-shell";
import { ConsoleState, type ConsoleStateKind } from "@/components/console-state";

const states: Array<{ kind: ConsoleStateKind; title: string; description: string }> = [
  { kind: "loading", title: "Loading", description: "Waiting for a future local API response." },
  { kind: "empty", title: "Empty", description: "No data has been provided." },
  { kind: "error", title: "Error", description: "A future request failed without applying a change." },
  { kind: "unavailable", title: "Unavailable", description: "Data integration is not implemented." },
];

export default function FoundationStatesPage() {
  return <ConsoleShell title="Foundation states"><div className="grid gap-4 md:grid-cols-2">{states.map(state => <ConsoleState key={state.kind} {...state} />)}</div></ConsoleShell>;
}

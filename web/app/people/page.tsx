import type { Metadata } from "next";
import { ConsoleShell } from "@/components/console-shell";
import { DomainStatusView } from "@/components/domain-status-view";

export const metadata: Metadata = { title: "People" };
const definition = {
  source: "people",
  capability: "identity.person.read",
  title: "People",
  unavailableDescription: "The identity capability is unavailable or needs an approved adapter. Detailed identity records arrive in their owning later phase.",
  currentDescription: "It does not mean identity records, grants, or devices are available.",
} as const;

export default function PeoplePage() { return <ConsoleShell title="People"><DomainStatusView definition={definition} /></ConsoleShell>; }

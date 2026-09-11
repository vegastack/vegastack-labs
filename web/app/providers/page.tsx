import type { Metadata } from "next";
import { ConsoleShell } from "@/components/console-shell";
import { DomainStatusView } from "@/components/domain-status-view";

export const metadata: Metadata = { title: "Providers" };
const definition = {
  source: "providers",
  capability: "adapter.status.read",
  title: "Providers",
  unavailableDescription: "The adapter capability is unavailable or needs an approved adapter. Detailed provider records arrive in their owning later phase.",
  currentDescription: "It does not mean provider records, connections, or operations are available.",
} as const;

export default function ProvidersPage() { return <ConsoleShell title="Providers"><DomainStatusView definition={definition} /></ConsoleShell>; }

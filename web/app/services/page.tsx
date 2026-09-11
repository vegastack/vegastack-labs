import type { Metadata } from "next";
import { ConsoleShell } from "@/components/console-shell";
import { DomainStatusView } from "@/components/domain-status-view";

export const metadata: Metadata = { title: "Services" };
const definition = {
  source: "services",
  capability: "service.read",
  title: "Services",
  unavailableDescription: "The service capability is unavailable or needs an approved adapter. Detailed service records arrive in their owning later phase.",
  currentDescription: "It does not mean service records, placement, exposure, or operations are available.",
} as const;

export default function ServicesPage() { return <ConsoleShell title="Services"><DomainStatusView definition={definition} /></ConsoleShell>; }

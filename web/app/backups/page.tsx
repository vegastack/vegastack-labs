import type { Metadata } from "next";
import { ConsoleShell } from "@/components/console-shell";
import { DomainStatusView } from "@/components/domain-status-view";

export const metadata: Metadata = { title: "Backups" };
const definition = {
  source: "backups",
  capability: "backup.status.read",
  title: "Backups",
  unavailableDescription: "The backup capability is unavailable or needs an approved adapter. Detailed recovery records arrive in their owning later phase.",
  currentDescription: "It does not mean a recovery point, integrity check, or recovery operation is available.",
} as const;

export default function BackupsPage() { return <ConsoleShell title="Backups"><DomainStatusView definition={definition} /></ConsoleShell>; }

import type { Metadata } from "next";
import { ConsoleShell } from "@/components/console-shell";
import { ConsoleState } from "@/components/console-state";

export const metadata: Metadata = { title: "Console foundation" };

export default function DashboardPage() {
  return (
    <ConsoleShell title="Console foundation">
      <ConsoleState kind="unavailable" title="Operational dashboard unavailable" description="Data integration is not implemented. This preview proves the shared layout and states without claiming that the control plane is connected or healthy." />
    </ConsoleShell>
  );
}

import type { Metadata } from "next";
import { ConsoleShell } from "@/components/console-shell";
import { ProvidersView } from "@/components/providers-view";
export const metadata: Metadata = { title: "Providers" };
export default function ProvidersPage() {
  return (
    <ConsoleShell title="Providers">
      <ProvidersView />
    </ConsoleShell>
  );
}

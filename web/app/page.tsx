import type { Metadata } from "next";
import { ConsoleShell } from "@/components/console-shell";
import { OverviewView } from "@/components/overview-view";

export const metadata: Metadata = { title: "Overview" };

export default function Home() {
  return (
    <ConsoleShell title="Overview">
      <OverviewView />
    </ConsoleShell>
  );
}

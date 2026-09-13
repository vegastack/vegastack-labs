import type { Metadata } from "next";
import { ChangesWorkspace } from "@/components/changes-workspace";
import { ConsoleShell } from "@/components/console-shell";

export const metadata: Metadata = { title: "Changes" };

export default function ChangesPage() {
  return <ConsoleShell title="Changes"><ChangesWorkspace /></ConsoleShell>;
}

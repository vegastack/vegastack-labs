import type { Metadata } from "next";
import { ConsoleShell } from "@/components/console-shell";
import { GatesView } from "@/components/gates-view";

export const metadata: Metadata = { title: "Gates" };
export default function GatesPage() { return <ConsoleShell title="Gates"><GatesView /></ConsoleShell>; }

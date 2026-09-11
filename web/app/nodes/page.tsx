import type { Metadata } from "next";
import { ConsoleShell } from "@/components/console-shell";
import { NodesView } from "@/components/nodes-view";

export const metadata: Metadata = { title: "Nodes" };
export default function NodesPage() { return <ConsoleShell title="Nodes"><NodesView /></ConsoleShell>; }

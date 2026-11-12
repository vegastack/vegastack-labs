import type { Metadata } from "next";
import { ConsoleShell } from "@/components/console-shell";
import { GatesView } from "@/components/gates-view";

export const metadata: Metadata = { title: "Checks" };
export default function GatesPage() { return <ConsoleShell title="Checks"><noscript><p>JavaScript is unavailable. Inspect gates with <code>vsk-labs gate list --json</code> and <code>vsk-labs gate inspect --gate-id &lt;id&gt; --json</code>. Draft evidence through the local CLI; no browser action was attempted.</p></noscript><GatesView /></ConsoleShell>; }

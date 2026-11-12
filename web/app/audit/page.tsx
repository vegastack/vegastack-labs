import type { Metadata } from "next";
import { AuditView } from "@/components/audit-view";
import { ConsoleShell } from "@/components/console-shell";

export const metadata: Metadata = { title: "History checks" };
export default function AuditPage() { return <ConsoleShell title="History checks"><noscript><p>JavaScript is unavailable. Inspect continuity with <code>vsk-labs audit checkpoints --json</code> and <code>vsk-labs audit verify --json</code>. No browser action was attempted.</p></noscript><AuditView /></ConsoleShell>; }

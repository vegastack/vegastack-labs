import type { Metadata } from "next";
import { ConsoleShell } from "@/components/console-shell";
import { BackupRecoveryView } from "@/components/backup-recovery-view";

export const metadata: Metadata = { title: "Backups" };
export default function BackupsPage() { return <ConsoleShell title="Backups"><noscript><p>JavaScript is unavailable. Inspect backup and recovery state with <code>vsk-labs backup status --json</code>, <code>vsk-labs restore plan --help</code>, and <code>vsk-labs schedule list --json</code>. No browser action was attempted.</p></noscript><BackupRecoveryView /></ConsoleShell>; }

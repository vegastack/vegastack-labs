import type { Metadata } from "next";
import { ConsoleShell } from "@/components/console-shell";
import { ConsoleState } from "@/components/console-state";
import Link from "next/link";

export const metadata: Metadata = { title: "Service unavailable" };

export default function UnavailablePage() {
  return <ConsoleShell title="Service unavailable"><ConsoleState kind="unavailable" title="This feature is not available" description="This address does not provide an implemented feature. It does not report the connection or health of your controller." action={<Link prefetch={false} href="/" className="underline">Return to Overview</Link>} /></ConsoleShell>;
}

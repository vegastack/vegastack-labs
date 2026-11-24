import type { Metadata } from "next";
import { ConsoleShell } from "@/components/console-shell";
import { ServicesView } from "@/components/services-view";

export const metadata: Metadata = { title: "Applications" };
export default function ServicesPage() { return <ConsoleShell title="Applications"><ServicesView /></ConsoleShell>; }

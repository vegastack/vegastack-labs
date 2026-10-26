import type { Metadata } from "next";
import { ConsoleShell } from "@/components/console-shell";
import { ServicesView } from "@/components/services-view";

export const metadata: Metadata = { title: "Services" };
export default function ServicesPage() { return <ConsoleShell title="Services"><ServicesView /></ConsoleShell>; }

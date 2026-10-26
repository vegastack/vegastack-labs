import type { Metadata } from "next";
import { ConsoleShell } from "@/components/console-shell";
import { PeopleView } from "@/components/people-view";
export const metadata: Metadata = { title: "People" };
export default function PeoplePage() {
  return (
    <ConsoleShell title="People">
      <PeopleView />
    </ConsoleShell>
  );
}

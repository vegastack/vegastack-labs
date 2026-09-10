import { ConsoleShell } from "@/components/console-shell";
import { ConsoleState } from "@/components/console-state";

export default function Home() {
  return (
    <ConsoleShell title="Overview">
      <ConsoleState kind="empty" title="No control-plane data yet" description="This is the static Console foundation. Data integration is not implemented, so no inventory, plans, or health status is shown." />
    </ConsoleShell>
  );
}

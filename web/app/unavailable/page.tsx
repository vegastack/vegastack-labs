import { ConsoleShell } from "@/components/console-shell";
import { ConsoleState } from "@/components/console-state";

export default function UnavailablePage() {
  return <ConsoleShell title="Service unavailable"><ConsoleState kind="unavailable" title="Control plane is not connected" description="This static preview has no server or API connection. Availability will be reported only after data integration is implemented." /></ConsoleShell>;
}

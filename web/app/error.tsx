"use client";

import { Button } from "@/components/ui/button";
import { ConsoleShell } from "@/components/console-shell";
import { ConsoleState } from "@/components/console-state";

export default function ErrorBoundary({ reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return <ConsoleShell title="Console error"><ConsoleState kind="error" title="The Console could not render" description="No operation was attempted. Try rendering this static view again." action={<Button onClick={reset}>Try again</Button>} /></ConsoleShell>;
}

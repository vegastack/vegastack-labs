"use client";

import { Button } from "@/components/ui/button";
import { ConsoleState } from "@/components/console-state";

export default function ErrorBoundary({ reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return <main aria-label="Console error" className="flex min-h-svh items-center justify-center p-4"><ConsoleState kind="error" title="The Console could not render" description="No operation was attempted. Try rendering this static view again." action={<Button onClick={reset}>Try again</Button>} /></main>;
}

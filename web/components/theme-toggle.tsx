"use client";

import { Moon, Sun } from "lucide-react";
import { useSyncExternalStore } from "react";
import { Button } from "@/components/ui/button";
import { useVegaStackTheme } from "@/components/ui/provider";

export function ThemeToggle() {
  const { resolvedTheme, setTheme } = useVegaStackTheme();
  const mounted = useSyncExternalStore(() => () => {}, () => true, () => false);
  if (!mounted) return <Button aria-label="Theme loading" variant="outline" size="icon-sm" disabled><Moon aria-hidden /></Button>;
  const dark = resolvedTheme === "dark";
  return (
    <Button aria-label={`Use ${dark ? "light" : "dark"} theme`} variant="outline" size="icon-sm" onClick={() => setTheme(dark ? "light" : "dark")}>
      {dark ? <Sun aria-hidden /> : <Moon aria-hidden />}
    </Button>
  );
}

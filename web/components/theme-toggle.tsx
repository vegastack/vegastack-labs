"use client";

import { Moon, Sun } from "lucide-react";
import { useSyncExternalStore } from "react";
import { IconButton } from "@/components/ui/icon-button";
import { useVegaStackTheme } from "@/components/ui/provider";

export function ThemeToggle() {
  const { resolvedTheme, setTheme } = useVegaStackTheme();
  const mounted = useSyncExternalStore(() => () => {}, () => true, () => false);
  if (!mounted) {
    return (
      <IconButton aria-label="Theme loading" variant="ghost" disabled>
        <Moon />
      </IconButton>
    );
  }
  const dark = resolvedTheme === "dark";
  return (
    <IconButton aria-label={`Use ${dark ? "light" : "dark"} theme`} variant="ghost" onClick={() => setTheme(dark ? "light" : "dark")}>
      {dark ? <Sun /> : <Moon />}
    </IconButton>
  );
}

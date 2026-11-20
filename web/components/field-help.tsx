"use client";

import type { ReactNode } from "react";
import { Popover } from "@base-ui/react/popover";
import { Info } from "lucide-react";
import { Button } from "@/components/ui/button";
import { FloatingSurface } from "@/components/ui/floating-surface";

/** Regent-style inline hint: hover or click to read, Escape or click away to close. */
export function FieldHelp({ label, children }: { label: string; children: ReactNode }) {
  const popupProps: Popover.Popup.Props = { initialFocus: false, finalFocus: false };
  return (
    <Popover.Root>
      <Popover.Trigger
        openOnHover
        delay={200}
        render={<Button type="button" variant="ghost" size="xs" aria-label={`Help: ${label}`} className="size-11 shrink-0 p-0 align-middle text-muted-foreground" />}
      >
        <Info aria-hidden className="size-4" />
      </Popover.Trigger>
      <FloatingSurface
        parts={{ Portal: Popover.Portal, Positioner: Popover.Positioner, Popup: Popover.Popup }}
        slot="field-help"
        surface="panel"
        positioning={{ side: "bottom", align: "start", sideOffset: 4 }}
        popupProps={popupProps}
        className="text-sm"
      >
        <Popover.Title className="mb-1 font-medium">{label}</Popover.Title>
        <Popover.Description render={<div />}>{children}</Popover.Description>
      </FloatingSurface>
    </Popover.Root>
  );
}

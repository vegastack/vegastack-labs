"use client";

import { useId, useState, type ReactNode } from "react";

/** Help stays open until dismissed and works with touch, pointer and keyboard. */
export function FieldHelp({ label, children }: { label: string; children: ReactNode }) {
  const [open, setOpen] = useState(false);
  const id = useId();
  return <span className="inline-flex max-w-full flex-col items-start gap-1 align-middle">
    <button type="button" aria-label={`Help: ${label}`} aria-expanded={open} aria-controls={id} onClick={() => setOpen(!open)} className="inline-flex size-11 shrink-0 items-center justify-center rounded-md text-sm font-medium text-muted-foreground hover:bg-muted focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring"><span aria-hidden className="inline-flex size-6 items-center justify-center rounded-full border border-border">i</span></button>
    <span id={id} hidden={!open} className="max-w-prose rounded-md border border-border bg-muted p-2 text-sm font-normal text-foreground">{children}</span>
  </span>;
}

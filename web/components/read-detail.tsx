"use client";

import { useEffect, type ReactNode, type RefObject } from "react";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";

export function ReadDetail({ title, open, onOpenChange, returnFocusRef, children }: { title: string; open: boolean; onOpenChange: (open: boolean) => void; returnFocusRef: RefObject<HTMLElement | null>; children: ReactNode }) {
  useEffect(() => { if (!open) returnFocusRef.current?.focus(); }, [open, returnFocusRef]);
  return <Sheet open={open} onOpenChange={onOpenChange}><SheetContent side="right" className="w-full sm:max-w-lg"><SheetHeader><SheetTitle>{title}</SheetTitle><SheetDescription>Authorized read-only record details.</SheetDescription></SheetHeader><div className="space-y-3 p-5">{children}</div></SheetContent></Sheet>;
}

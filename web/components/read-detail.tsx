"use client";

import { useEffect, type ReactNode, type RefObject } from "react";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";

export function ReadDetail({
  title,
  open,
  onOpenChange,
  returnFocusRef,
  children,
}: {
  title: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  returnFocusRef: RefObject<HTMLElement | null>;
  children: ReactNode;
}) {
  useEffect(() => {
    if (!open) returnFocusRef.current?.focus();
  }, [open, returnFocusRef]);
  return (
    <Sheet open={open} onOpenChange={onOpenChange} side="right">
      <SheetContent size="md" className="[&_[data-slot=sheet-close]]:size-11">

        <SheetHeader>
          <SheetTitle className="capitalize">{title}</SheetTitle>
          <SheetDescription>Authorized read-only record details.</SheetDescription>
        </SheetHeader>
        <div className="flex flex-col gap-3 p-5">{children}</div>
      </SheetContent>
    </Sheet>
  );
}
